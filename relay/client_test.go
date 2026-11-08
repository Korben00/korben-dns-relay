package relay

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func clientTestQuery() []byte {
	// Iterative NS query for the root; no real upstream is contacted.
	return []byte{0xde, 0xad, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1}
}

func clientTestReply() []byte {
	p := clientTestQuery()
	p[2] = 0x84 // QR, AA.
	return p
}

func clientTestQueryEDNS(size uint16) []byte {
	p := clientTestQuery()
	p[11] = 1 // One EDNS OPT.
	return append(p, 0, 0, 41, byte(size>>8), byte(size), 0, 0, 0x80, 0, 0, 0)
}

func clientTestToken() string { return strings.Repeat("ab", 32) }

func clientTestTLS(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func clientTestRoots(server *httptest.Server) *x509.CertPool {
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	return roots
}

func clientTestNew(t *testing.T, server *httptest.Server, base string, options ClientOptions) *Client {
	t.Helper()
	options.RootCAs = clientTestRoots(server)
	c, err := NewClient(base, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdleConnections)
	return c
}

func TestRelayClientWireAndAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target string
		tcp    bool
		prefix []byte
		token  string
	}{
		{"UDP IPv4", "198.41.0.4", false, []byte{0, 4, 198, 41, 0, 4}, ""},
		{"TCP IPv6", "2001:503:ba3e::2:30", true, []byte{1, 6, 0x20, 1, 5, 3, 0xba, 0x3e, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0x30}, clientTestToken()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := clientTestTLS(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/relay/v1/query" || r.URL.RawQuery != "" {
					t.Error("unexpected HTTP method or URL")
				}
				if r.Header.Get("Content-Type") != "application/octet-stream" || r.Header.Get("Accept") != "application/octet-stream" ||
					r.Header.Get("Accept-Encoding") != "identity" || r.Header.Get("Cache-Control") != "no-store" {
					t.Error("unexpected request media/cache headers")
				}
				if r.Header.Get("User-Agent") != "" || r.Header.Get("Cookie") != "" {
					t.Error("unnecessary client identifiers sent")
				}
				wantAuth := ""
				if tc.token != "" {
					wantAuth = "Bearer " + tc.token
				}
				if r.Header.Get("Authorization") != wantAuth {
					t.Error("unexpected authentication header")
				}
				body, err := io.ReadAll(r.Body)
				if err != nil || !bytes.Equal(body, append(tc.prefix, clientTestQuery()...)) {
					t.Error("unexpected target or DNS wire payload")
				}
				w.Header().Set("Content-Type", "application/octet-stream")
				_, _ = w.Write(clientTestReply())
			})
			c := clientTestNew(t, server, server.URL+"/relay/", ClientOptions{BearerToken: tc.token})
			got, err := c.Query(context.Background(), netip.MustParseAddr(tc.target), tc.tcp, clientTestQuery())
			if err != nil || !bytes.Equal(got, clientTestReply()) {
				t.Fatalf("query failed: %v", err)
			}
		})
	}
}

func TestRelayClientRejectsBadOptions(t *testing.T) {
	for _, endpoint := range []string{
		"http://relay.test", "https:relay.test", "https:///missing-host", "https://", "//relay.test",
		"https://user:password@relay.test", "https://relay.test?secret", "https://relay.test?",
		"https://relay.test#secret", "https://relay.test#", "https://relay.test:0", "https://relay.test:",
		"https://relay.test:65536", "https://relay.test:bad", "https://[fe80::1%25en0]", "https://relay.test/one/../two",
		"https://relay.test/foo%2fbar", "https://relay.test/%zz", "https://relay.test/raw space",
	} {
		if _, err := NewClient(endpoint, ClientOptions{}); !errors.Is(err, ErrRelayEndpoint) {
			t.Fatalf("accepted invalid URL: %q", endpoint)
		}
	}
	for _, token := range []string{"token with space", "token\nInjected: header", "é", strings.Repeat("g", 64), strings.Repeat("a", 63), strings.Repeat("a", 65)} {
		if _, err := NewClient("https://relay.test", ClientOptions{BearerToken: token}); !errors.Is(err, ErrRelayToken) {
			t.Fatal("accepted invalid token")
		}
	}
	for _, addr := range []string{"0.0.0.0", "::", "::ffff:0.0.0.0", "224.0.0.1", "fe80::1%en0"} {
		if _, err := NewClient("https://relay.test", ClientOptions{BootstrapIP: netip.MustParseAddr(addr)}); !errors.Is(err, ErrRelayBootstrap) {
			t.Fatal("accepted invalid bootstrap address")
		}
	}
	for _, timeout := range []time.Duration{-time.Second, 31 * time.Second} {
		if _, err := NewClient("https://relay.test", ClientOptions{Timeout: timeout}); !errors.Is(err, ErrRelayTimeout) {
			t.Fatal("accepted invalid timeout")
		}
	}
}

func TestRelayClientBootstrapPreservesVerifiedHostname(t *testing.T) {
	var requests atomic.Int32
	server := clientTestTLS(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || r.TLS.ServerName != "example.com" {
			t.Error("bootstrap did not preserve the HTTPS name in TLS SNI")
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(clientTestReply())
	})
	ip, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := netip.MustParseAddr(ip)
	if err := server.Certificate().VerifyHostname("example.com"); err != nil {
		t.Fatal("httptest TLS certificate fixture changed")
	}
	// Both connections use the loopback IP from the fixture, while the
	// certificate still has to cover the configured URL hostname.
	good := clientTestNew(t, server, "https://example.com:"+port, ClientOptions{BootstrapIP: bootstrap})
	bad := clientTestNew(t, server, "https://wrong.invalid:"+port, ClientOptions{BootstrapIP: bootstrap})
	target := netip.MustParseAddr("198.41.0.4")
	if _, err := good.Query(context.Background(), target, false, clientTestQuery()); err != nil {
		t.Fatalf("trusted bootstrap did not connect: %v", err)
	}
	if _, err := bad.Query(context.Background(), target, false, clientTestQuery()); !errors.Is(err, ErrRelayTransport) {
		t.Fatalf("wrong certificate name not rejected: %v", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("unexpected number of authenticated requests: %d", requests.Load())
	}
}

func TestRelayClientRejectsUntrustedTLS(t *testing.T) {
	server := clientTestTLS(t, func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("query reached a TLS server without an approved trust root")
	})
	c, err := NewClient(server.URL, ClientOptions{RootCAs: x509.NewCertPool()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdleConnections)
	if _, err := c.Query(context.Background(), netip.MustParseAddr("198.41.0.4"), false, clientTestQuery()); !errors.Is(err, ErrRelayTransport) {
		t.Fatalf("untrusted TLS connection not rejected: %v", err)
	}
}

func TestRelayClientRefusesTLS12(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("query reached a server without TLS 1.3")
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MaxVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	c := clientTestNew(t, server, server.URL, ClientOptions{})
	if _, err := c.Query(context.Background(), netip.MustParseAddr("198.41.0.4"), false, clientTestQuery()); !errors.Is(err, ErrRelayTransport) {
		t.Fatalf("TLS downgrade not rejected: %v", err)
	}
}

func TestRelayClientDoesNotRedirectOrExposeBody(t *testing.T) {
	var redirected atomic.Bool
	server := clientTestTLS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/query" {
			redirected.Store(true)
		}
		w.Header().Set("Location", "/redirected")
		w.WriteHeader(http.StatusFound)
		_, _ = io.WriteString(w, "DNS-query-data and private bearer token")
	})
	c := clientTestNew(t, server, server.URL, ClientOptions{BearerToken: clientTestToken()})
	transport, ok := c.http.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || c.http.Jar != nil || !transport.DisableCompression {
		t.Fatal("relay transport must not use environment proxies, cookies, or compression")
	}
	_, err := c.Query(context.Background(), netip.MustParseAddr("198.41.0.4"), false, clientTestQuery())
	var status *HTTPStatusError
	if !errors.As(err, &status) || status.StatusCode != 302 || err.Error() != "DNS relay HTTP status 302" || redirected.Load() {
		t.Fatal("redirect was followed or an unsafe status error was exposed")
	}
}

func TestRelayClientResponseBoundsAndEnvelope(t *testing.T) {
	for _, tc := range []struct {
		name     string
		tcp      bool
		edns     uint16
		body     []byte
		media    string
		encoding string
		chunked  bool
		wantOK   bool
	}{
		{"valid UDP", false, 0, clientTestReply(), MediaType, "", false, true},
		{"max UDP without EDNS", false, 0, append(clientTestReply(), make([]byte, 512-17)...), MediaType, "", false, true},
		{"over 512 without EDNS", false, 0, append(clientTestReply(), make([]byte, 513-17)...), MediaType, "", false, false},
		{"max advertised UDP", false, 600, append(clientTestReply(), make([]byte, 600-17)...), MediaType, "", false, true},
		{"over advertised UDP", false, 600, append(clientTestReply(), make([]byte, 601-17)...), MediaType, "", true, false},
		{"max UDP", false, 1232, append(clientTestReply(), make([]byte, 1232-17)...), MediaType, "", false, true},
		{"over UDP declared", false, 1232, append(clientTestReply(), make([]byte, 1233-17)...), MediaType, "", false, false},
		{"over UDP chunked", false, 1232, append(clientTestReply(), make([]byte, 1233-17)...), MediaType, "", true, false},
		{"max TCP", true, 0, append(clientTestReply(), make([]byte, 65535-17)...), MediaType, "", false, true},
		{"over TCP chunked", true, 0, append(clientTestReply(), make([]byte, 65536-17)...), MediaType, "", true, false},
		{"empty reply", false, 0, nil, MediaType, "", false, false},
		{"short reply", false, 0, clientTestReply()[:11], MediaType, "", true, false},
		{"wrong ID", false, 0, append([]byte{0, 0}, clientTestReply()[2:]...), MediaType, "", false, false},
		{"not a response", false, 0, clientTestQuery(), MediaType, "", false, false},
		{"wrong media type", false, 0, clientTestReply(), "text/plain", "", false, false},
		{"compressed reply", false, 0, clientTestReply(), MediaType, "gzip", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := clientTestTLS(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.media)
				if tc.encoding != "" {
					w.Header().Set("Content-Encoding", tc.encoding)
				}
				if tc.chunked {
					w.(http.Flusher).Flush()
				} else {
					w.Header().Set("Content-Length", strconv.Itoa(len(tc.body)))
				}
				_, _ = w.Write(tc.body)
			})
			c := clientTestNew(t, server, server.URL, ClientOptions{})
			query := clientTestQuery()
			if tc.edns != 0 {
				query = clientTestQueryEDNS(tc.edns)
			}
			got, err := c.Query(context.Background(), netip.MustParseAddr("198.41.0.4"), tc.tcp, query)
			if tc.wantOK {
				if err != nil || !bytes.Equal(got, tc.body) {
					t.Fatalf("valid DNS response rejected: %v", err)
				}
			} else if !errors.Is(err, ErrRelayResponse) || got != nil {
				t.Fatalf("invalid DNS response accepted: %v", err)
			}
		})
	}
}

func TestRelayClientRejectsForgedQuestionOrOpcode(t *testing.T) {
	q := append(clientTestQuery()[:12], 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1)
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
		ok     bool
	}{
		{"matching name with different case", func(w []byte) { w[13] = 'T' }, true},
		{"forged QNAME", func(w []byte) { w[13] = 'b' }, false},
		{"forged QTYPE", func(w []byte) { w[len(w)-3] = 28 }, false},
		{"forged QCLASS", func(w []byte) { w[len(w)-1] = 3 }, false},
		{"forged opcode", func(w []byte) { w[2] |= 0x08 }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := clientTestTLS(t, func(w http.ResponseWriter, _ *http.Request) {
				r := bytes.Clone(q)
				r[2] = 0x84
				tc.mutate(r)
				w.Header().Set("Content-Type", MediaType)
				_, _ = w.Write(r)
			})
			c := clientTestNew(t, server, server.URL, ClientOptions{})
			r, err := c.Query(context.Background(), netip.MustParseAddr("198.41.0.4"), false, q)
			if tc.ok && (err != nil || r == nil) {
				t.Fatalf("case-only DNS change rejected: %v", err)
			}
			if !tc.ok && (!errors.Is(err, ErrRelayResponse) || r != nil) {
				t.Fatalf("forged DNS question/opcode accepted: %v", err)
			}
		})
	}
}

func TestRelayClientRejectsMalformedRequestsBeforeDial(t *testing.T) {
	// A numeric endpoint makes even a regression unable to perform a lookup.
	c, err := NewClient("https://127.0.0.1:1", ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdleConnections)
	var dials atomic.Int32
	c.http.Transport.(*http.Transport).DialContext = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("unexpected dial")
	}
	recursive := clientTestQuery()
	recursive[2] = 1
	for _, wire := range [][]byte{nil, make([]byte, 11), make([]byte, 1233), clientTestReply(), recursive, clientTestQueryEDNS(4096)} {
		if _, err := c.Query(context.Background(), netip.MustParseAddr("198.41.0.4"), false, wire); !errors.Is(err, ErrRelayRequest) {
			t.Fatalf("bad request was not rejected before dialing: %v", err)
		}
	}
	for _, addr := range []netip.Addr{
		{}, netip.MustParseAddr("fe80::1%en0"), netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("169.254.169.254"),
		netip.MustParseAddr("fd00::1"), netip.MustParseAddr("::ffff:198.41.0.4"),
	} {
		if _, err := c.Query(context.Background(), addr, false, clientTestQuery()); !errors.Is(err, ErrRelayTarget) {
			t.Fatalf("bad target was not rejected before dialing: %v", err)
		}
	}
	if dials.Load() != 0 {
		t.Fatal("client dialed the relay before rejecting invalid input")
	}
}

func TestRelayClientCancelsWhileReading(t *testing.T) {
	started := make(chan struct{})
	stop := make(chan struct{})
	defer close(stop)
	server := clientTestTLS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(clientTestReply())
		w.(http.Flusher).Flush()
		close(started)
		select {
		case <-r.Context().Done():
		case <-stop:
		}
	})
	c := clientTestNew(t, server, server.URL, ClientOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := c.Query(ctx, netip.MustParseAddr("198.41.0.4"), false, clientTestQuery())
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("relay request did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("client did not preserve cancellation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client did not terminate canceled response read")
	}
}
