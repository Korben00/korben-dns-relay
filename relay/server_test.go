package relay

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var testAuthority = netip.MustParseAddr("198.41.0.4")
var testKey = strings.Repeat("ab", 32) // deterministic fixture, never used by the executable

func rootNS() []byte { return []byte{1, 2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1} }

func answerFor(wire []byte) []byte {
	out := bytes.Clone(wire)
	out[2] = 0x84
	return out
}

func frame(tcp bool, ip netip.Addr, wire []byte) []byte {
	b := []byte{0, 4}
	if tcp {
		b[0] = 1
	}
	if !ip.Is4() {
		b[1] = 6
	}
	return append(append(b, ip.AsSlice()...), wire...)
}

func newTestServer(t *testing.T, cfg Config) *Server {
	t.Helper()
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func request(s *Server, method, path, token string, b []byte) int {
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	if !strings.HasPrefix(path, "http:") {
		r.TLS = &tls.ConnectionState{}
	}
	r.Header.Set("Content-Type", MediaType)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w.Code
}

func TestPolicyRejectsUnsafeTargetsBeforeExchange(t *testing.T) {
	s := newTestServer(t, Config{Token: testKey, AnyPublicAuthority: true, Deny: []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24")}})
	s.own[netip.MustParseAddr("9.9.9.9")] = struct{}{}
	s.exchange = func(context.Context, packet) ([]byte, error) { t.Fatal("denied packet was sent"); return nil, nil }
	for _, raw := range []string{"0.0.0.0", "127.0.0.1", "10.0.0.1", "100.100.100.200", "169.254.169.254", "168.63.129.16", "172.31.0.1", "192.168.1.1", "198.18.0.1", "224.0.0.1", "255.255.255.255", "8.8.8.8", "9.9.9.9", "::", "::1", "fd00:ec2::254", "fe80::1", "64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::", "2001:db8::1", "ff02::1"} {
		t.Run(raw, func(t *testing.T) {
			if got := request(s, "POST", QueryPath, testKey, frame(false, netip.MustParseAddr(raw), rootNS())); got != 403 {
				t.Fatalf("status %d", got)
			}
		})
	}
	if got := request(s, "POST", QueryPath, testKey, frame(false, netip.MustParseAddr("::ffff:127.0.0.1"), rootNS())); got != 400 {
		t.Fatalf("mapped address status %d", got)
	}
}

func TestAuthAndHTTPRejectWithoutExchange(t *testing.T) {
	s := newTestServer(t, Config{Token: testKey, Allow: []netip.Addr{testAuthority}})
	s.exchange = func(context.Context, packet) ([]byte, error) { t.Fatal("denied packet was sent"); return nil, nil }
	b := frame(false, testAuthority, rootNS())
	for _, tt := range []struct {
		method, path, key string
		want              int
	}{
		{"POST", QueryPath, "", 401}, {"POST", QueryPath, strings.Repeat("aa", 32), 401},
		{"POST", "http://example.test" + QueryPath, testKey, 404},
		{"POST", QueryPath + "?private=query", testKey, 404}, {"POST", "/v1/%71uery", testKey, 404},
		{"CONNECT", QueryPath, testKey, 405},
	} {
		if got := request(s, tt.method, tt.path, tt.key, b); got != tt.want {
			t.Fatalf("%+v: %d", tt, got)
		}
	}
	r := httptest.NewRequest("POST", "https://test.invalid"+QueryPath, bytes.NewReader(b))
	r.Header.Add("Authorization", "Bearer "+testKey)
	r.Header.Add("Authorization", "Bearer "+testKey)
	r.Header.Set("Content-Type", MediaType)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("ambiguous authorization %d", w.Code)
	}
	r = httptest.NewRequest("POST", "https://test.invalid"+QueryPath, strings.NewReader(strings.Repeat("x", maxFrame+1)))
	r.ContentLength = -1
	r.Header.Set("Authorization", "Bearer "+testKey)
	r.Header.Set("Content-Type", MediaType)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 413 || w.Body.Len() != 0 {
		t.Fatalf("oversize stream %d", w.Code)
	}
}

func TestPublicRequiresExactAllowlist(t *testing.T) {
	for _, cfg := range []Config{
		{Public: true}, {Public: true, AnyPublicAuthority: true},
		{Public: true, Token: testKey, Allow: []netip.Addr{testAuthority}},
		{AnyPublicAuthority: true}, {Token: testKey, Allow: []netip.Addr{netip.MustParseAddr("127.0.0.1")}},
	} {
		if _, err := NewServer(cfg); err == nil {
			t.Fatal("unsafe configuration accepted")
		}
	}
	s := newTestServer(t, Config{Public: true, Allow: []netip.Addr{testAuthority}})
	s.exchange = func(_ context.Context, p packet) ([]byte, error) {
		if p.target != testAuthority {
			t.Fatal("unlisted destination")
		}
		return answerFor(p.wire), nil
	}
	if got := request(s, "POST", QueryPath, "", frame(false, netip.MustParseAddr("8.8.8.8"), rootNS())); got != 403 {
		t.Fatalf("unlisted %d", got)
	}
	if got := request(s, "POST", QueryPath, "", frame(false, testAuthority, rootNS())); got != 200 {
		t.Fatalf("allowed %d", got)
	}
}

func TestWireRejectsUnexpectedQueryFeatures(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func([]byte) []byte
	}{
		{"RD", func(w []byte) []byte { w[2] |= 1; return w }},
		{"opcode", func(w []byte) []byte { w[2] |= 8; return w }},
		{"QR", func(w []byte) []byte { w[2] |= 128; return w }},
		{"transfer", func(w []byte) []byte { w[14] = 252; return w }},
		{"any", func(w []byte) []byte { w[14] = 255; return w }},
		{"compression", func(w []byte) []byte { w[12] = 192; return w }},
		{"trailing", func(w []byte) []byte { return append(w, 0) }},
		{"extra question", func(w []byte) []byte { w[5] = 2; return w }},
		{"answer section", func(w []byte) []byte { w[7] = 1; return w }},
		{"ECS", func(w []byte) []byte { w[11] = 1; return append(w, 0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 4, 0, 8, 0, 0) }},
		{"nonzero padding", func(w []byte) []byte {
			w[11] = 1
			return append(w, 0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 5, 0, 12, 0, 1, 1)
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := checkQuery(tt.change(rootNS())); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	q := rootNS()
	q[11] = 1
	q = append(q, 0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 5, 0, 12, 0, 1, 0)
	p, err := parseFrame(frame(false, testAuthority, q))
	if err != nil || udpLimit(p) != 1232 {
		t.Fatalf("valid EDNS rejected: %v", err)
	}
}

func TestLimiterKeepsBothBudgets(t *testing.T) {
	l := limiter{targets: make(map[netip.Prefix]bucket)}
	now := time.Now()
	for i := 0; i < 12; i++ {
		if !l.allow(testAuthority, now) {
			t.Fatal("burst was blocked")
		}
	}
	for range 60 {
		if l.allow(netip.MustParseAddr("198.41.0.5"), now) {
			t.Fatal("same target subnet bypassed quota")
		}
	}
	if !l.allow(netip.MustParseAddr("9.9.9.9"), now) {
		t.Fatal("rejected target requests drained the global budget")
	}
	if !l.allow(testAuthority, now.Add(time.Second)) {
		t.Fatal("quota never refilled")
	}
	l = limiter{targets: make(map[netip.Prefix]bucket)}
	for i := 0; i < 30; i++ {
		if !l.allow(netip.AddrFrom4([4]byte{8, 0, byte(i), 1}), now) {
			t.Fatal("global burst was blocked")
		}
	}
	if l.allow(netip.MustParseAddr("9.9.9.9"), now) {
		t.Fatal("global quota bypass")
	}
	for i := 0; i < 1100; i++ {
		l.allow(netip.AddrFrom4([4]byte{8, byte(i >> 8), byte(i), 1}), now.Add(time.Duration(i+1)*time.Second/20))
	}
	if len(l.targets) > 4096 {
		t.Fatal("unbounded quota map")
	}
}

func TestForwardHTTPSViaRealUDPAndTCP(t *testing.T) {
	for _, network := range []string{"udp4", "tcp4", "udp6", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			tcp := strings.HasPrefix(network, "tcp")
			host := "127.0.0.1:0"
			if strings.HasSuffix(network, "6") {
				host = "[::1]:0"
			}
			addr, done := fakeAuthority(t, network, host)
			s := newTestServer(t, Config{Token: testKey, Allow: []netip.Addr{testAuthority}})
			s.exchange = func(ctx context.Context, p packet) ([]byte, error) { return forward(ctx, p, network, addr) }
			httpTest := httptest.NewTLSServer(s)
			defer httpTest.Close()
			pool := x509.NewCertPool()
			pool.AddCert(httpTest.Certificate())
			c, err := NewClient(httpTest.URL, ClientOptions{BearerToken: testKey, RootCAs: pool})
			if err != nil {
				t.Fatal(err)
			}
			answer, err := c.Query(context.Background(), testAuthority, tcp, rootNS())
			want := answerFor(rootNS())
			if !tcp {
				want[2] |= 2
			} // preserve TC so the resolver can choose TCP
			if err != nil || !bytes.Equal(answer, want) {
				t.Fatalf("reply did not preserve question/ID/flags: %v", err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("test authority did not finish")
			}
		})
	}
}

func fakeAuthority(t *testing.T, network, host string) (string, chan error) {
	t.Helper()
	done := make(chan error, 1)
	if strings.HasPrefix(network, "tcp") {
		l, err := net.Listen(network, host)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
		go func() {
			c, err := l.Accept()
			if err != nil {
				done <- err
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			var n [2]byte
			if _, err = io.ReadFull(c, n[:]); err != nil {
				done <- err
				return
			}
			wire := make([]byte, binary.BigEndian.Uint16(n[:]))
			if _, err = io.ReadFull(c, wire); err != nil {
				done <- err
				return
			}
			reply := answerFor(wire)
			for _, b := range append(n[:], reply...) {
				if _, err = c.Write([]byte{b}); err != nil {
					done <- err
					return
				}
			}
			done <- nil
		}()
		return l.Addr().String(), done
	}
	l, err := net.ListenPacket(network, host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		_ = l.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, maxQuery)
		n, remote, err := l.ReadFrom(buf)
		if err != nil {
			done <- err
			return
		}
		if n < 17 {
			done <- errors.New("short query")
			return
		}
		bad := answerFor(buf[:n])
		bad[0] ^= 1
		if _, err = l.WriteTo(bad, remote); err != nil {
			done <- err
			return
		}
		good := answerFor(buf[:n])
		good[2] |= 2
		_, err = l.WriteTo(good, remote)
		done <- err
	}()
	return l.LocalAddr().String(), done
}

func TestOutboundCancellation(t *testing.T) {
	l, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, _ := parseFrame(frame(false, testAuthority, rootNS()))
	done := make(chan error, 1)
	go func() { _, err := forward(ctx, p, "udp4", l.LocalAddr().String()); done <- err }()
	_ = l.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := l.ReadFrom(make([]byte, 64)); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled query returned a response")
		}
	case <-time.After(time.Second):
		t.Fatal("outbound did not release on cancellation")
	}
}

func FuzzFrame(f *testing.F) {
	f.Add(frame(false, testAuthority, rootNS()))
	f.Add(frame(true, netip.MustParseAddr("2001:503:ba3e::2:30"), rootNS()))
	f.Add([]byte{0, 6})
	f.Fuzz(func(t *testing.T, raw []byte) {
		p, err := parseFrame(raw)
		if err == nil {
			if len(p.wire) > maxQuery || p.end < 17 || p.end > len(p.wire) {
				t.Fatal("invalid acceptance")
			}
			if limit := udpLimit(p); limit < 512 || limit > 1232 {
				t.Fatal("invalid UDP limit")
			}
			if !responseMatches(p, answerFor(p.wire)) {
				t.Fatal("matching reply rejected")
			}
		}
		_, _ = questionEnd(raw)
	})
}
