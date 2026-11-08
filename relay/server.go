package relay

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type Config struct {
	// Token is 32 random bytes, encoded as exactly 64 hexadecimal digits.
	Token string
	// Public requires an explicit list of exact destination IPs.
	Public bool
	Allow  []netip.Addr
	Deny   []netip.Prefix
	// AnyPublicAuthority is allowed only with authentication. No IP ownership
	// or authority is proved by the address policy.
	AnyPublicAuthority bool
}

type Server struct {
	public, any bool
	key         [32]byte
	allow       map[netip.Addr]struct{}
	deny        []netip.Prefix
	own         map[netip.Addr]struct{}
	work        chan struct{}
	limit       limiter
	exchange    func(context.Context, packet) ([]byte, error)
}

func NewServer(config Config) (*Server, error) {
	if config.Public && (config.Token != "" || config.AnyPublicAuthority) {
		return nil, errors.New("public mode requires an explicit allowlist and no token")
	}
	if len(config.Allow) > 256 || len(config.Deny) > 256 ||
		(len(config.Allow) == 0 && !config.AnyPublicAuthority) ||
		(len(config.Allow) > 0 && config.AnyPublicAuthority) {
		return nil, errors.New("configure either an exact destination list or authenticated public-address access")
	}
	s := &Server{
		public: config.Public, any: config.AnyPublicAuthority,
		allow: make(map[netip.Addr]struct{}), deny: append([]netip.Prefix(nil), config.Deny...),
		own: make(map[netip.Addr]struct{}), work: make(chan struct{}, 32),
		limit:    limiter{targets: make(map[netip.Prefix]bucket)},
		exchange: exchangeDNS,
	}
	if !config.Public {
		if !ValidToken(config.Token) {
			return nil, errors.New("a 64-digit hexadecimal token is required")
		}
		s.key = sha256.Sum256([]byte(config.Token))
	}
	for _, ip := range config.Allow {
		if !publicAddress(ip) {
			return nil, errors.New("non-public IP in destination list")
		}
		s.allow[ip] = struct{}{}
	}
	for _, p := range s.deny {
		if !p.IsValid() || p.Addr().Is4In6() {
			return nil, errors.New("invalid excluded network")
		}
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, errors.New("could not enumerate local interfaces")
	}
	for _, addr := range addrs {
		p, err := netip.ParsePrefix(addr.String())
		if err != nil {
			return nil, errors.New("could not parse a local interface address")
		}
		s.own[p.Addr().Unmap()] = struct{}{}
	}
	for ip := range s.allow {
		if !s.allowed(ip) {
			return nil, errors.New("destination conflicts with a local address or exclusion")
		}
	}
	return s, nil
}

func ValidToken(token string) bool {
	if len(token) != 64 {
		return false
	}
	var b [32]byte
	_, err := hex.Decode(b[:], []byte(token))
	return err == nil
}

func (s *Server) allowed(ip netip.Addr) bool {
	if !publicAddress(ip) {
		return false
	}
	if _, self := s.own[ip]; self {
		return false
	}
	for _, p := range s.deny {
		if p.Contains(ip) {
			return false
		}
	}
	_, allowed := s.allow[ip]
	return s.any || allowed
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.TLS == nil || r.URL.EscapedPath() != QueryPath || r.URL.RawQuery != "" || r.URL.ForceQuery {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.public {
		values := r.Header.Values("Authorization")
		if len(values) != 1 || len(values[0]) != 71 || !strings.HasPrefix(values[0], "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		given := sha256.Sum256([]byte(values[0][7:]))
		if subtle.ConstantTimeCompare(given[:], s.key[:]) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	contentType := r.Header.Values("Content-Type")
	if len(contentType) != 1 || contentType[0] != MediaType ||
		len(r.Header.Values("Content-Encoding")) != 0 {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}
	if r.ContentLength > maxFrame {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	select {
	case s.work <- struct{}{}:
		defer func() { <-s.work }()
	default:
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxFrame))
	if err != nil {
		var size *http.MaxBytesError
		if errors.As(err, &size) {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
		return
	}
	p, err := parseFrame(b)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !s.allowed(p.target) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if !s.limit.allow(p.target, time.Now()) {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	answer, err := s.exchange(ctx, p)
	if ctx.Err() != nil {
		w.WriteHeader(http.StatusGatewayTimeout)
		return
	}
	if err != nil || !responseMatches(p, answer) ||
		(!p.tcp && len(answer) > udpLimit(p)) || len(answer) > 65535 {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", MediaType)
	_, _ = w.Write(answer)
}

// Quotas are per instance and per destination network, not per visitor.
// No client identifiers or DNS content are retained. The table is bounded.
type bucket struct {
	tokens float64
	at     time.Time
}
type limiter struct {
	mu        sync.Mutex
	global    bucket
	targets   map[netip.Prefix]bucket
	nextSweep time.Time
}

func refill(b bucket, now time.Time, rate, burst float64) bucket {
	if b.at.IsZero() {
		return bucket{burst, now}
	}
	if now.Before(b.at) {
		return b
	}
	return bucket{min(burst, b.tokens+now.Sub(b.at).Seconds()*rate), now}
}

func (l *limiter) allow(ip netip.Addr, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.global = refill(l.global, now, 60, 30)
	if l.global.tokens < 1 {
		return false
	}
	bits := 48
	if ip.Is4() {
		bits = 24
	}
	key := netip.PrefixFrom(ip, bits).Masked()
	if now.After(l.nextSweep) {
		for k, b := range l.targets {
			if now.Sub(b.at) > time.Minute {
				delete(l.targets, k)
			}
		}
		l.nextSweep = now.Add(time.Second)
	}
	b, exists := l.targets[key]
	if !exists && len(l.targets) >= 4096 {
		return false
	}
	b = refill(b, now, 12, 12)
	if b.tokens < 1 {
		l.targets[key] = b
		return false
	}
	l.global.tokens--
	b.tokens--
	l.targets[key] = b
	return true
}

func exchangeDNS(ctx context.Context, p packet) ([]byte, error) {
	transport := "udp"
	if p.tcp {
		transport = "tcp"
	}
	if p.target.Is4() {
		transport += "4"
	} else {
		transport += "6"
	}
	return forward(ctx, p, transport, netip.AddrPortFrom(p.target, 53).String())
}

func forward(ctx context.Context, p packet, transport, address string) ([]byte, error) {
	original := p.wire[:2]
	p.wire = append([]byte(nil), p.wire...)
	if _, err := rand.Read(p.wire[:2]); err != nil {
		return nil, err
	}
	answer, err := exchangeAt(ctx, p, transport, address)
	if err != nil {
		return nil, err
	}
	if !responseMatches(p, answer) {
		return nil, errWire
	}
	copy(answer[:2], original)
	return answer, nil
}

// exchangeAt also lets tests use an isolated loopback authority and high
// port. Only exchangeDNS selects a production destination.
func exchangeAt(ctx context.Context, p packet, transport, address string) ([]byte, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, transport, address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	if p.tcp {
		frame := make([]byte, 2+len(p.wire))
		binary.BigEndian.PutUint16(frame[:2], uint16(len(p.wire)))
		copy(frame[2:], p.wire)
		if n, err := conn.Write(frame); err != nil || n != len(frame) {
			return nil, io.ErrShortWrite
		}
		var length [2]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return nil, err
		}
		out := make([]byte, int(binary.BigEndian.Uint16(length[:])))
		_, err := io.ReadFull(conn, out)
		return out, err
	}
	if n, err := conn.Write(p.wire); err != nil || n != len(p.wire) {
		return nil, io.ErrShortWrite
	}
	out := make([]byte, udpLimit(p)+1)
	// Read only from the connected authority. Ignore a small, bounded
	// number of unexpected packets before returning an upstream error.
	for range 4 {
		n, err := conn.Read(out)
		if err != nil {
			return nil, err
		}
		if n <= udpLimit(p) && responseMatches(p, out[:n]) {
			return out[:n], nil
		}
	}
	return nil, errWire
}
