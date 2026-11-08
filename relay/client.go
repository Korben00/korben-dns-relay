package relay

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	clientTCPLimit   = 65535
	clientTimeout    = 8 * time.Second
	clientMaxTimeout = 30 * time.Second
)

var (
	ErrRelayEndpoint  = errors.New("invalid HTTPS relay URL")
	ErrRelayBootstrap = errors.New("invalid relay bootstrap address")
	ErrRelayToken     = errors.New("invalid relay bearer token")
	ErrRelayTimeout   = errors.New("relay timeout must be between zero and 30 seconds")
	ErrRelayTarget    = errors.New("invalid DNS relay target address")
	ErrRelayRequest   = errors.New("invalid DNS relay request")
	ErrRelayResponse  = errors.New("invalid DNS relay response")
	ErrRelayTransport = errors.New("DNS relay connection failed")
)

// HTTPStatusError reports a refused relay request without exposing its URL,
// authentication header, DNS payload, or the response body.
type HTTPStatusError struct {
	StatusCode int
}

func (e *HTTPStatusError) Error() string {
	return "DNS relay HTTP status " + strconv.Itoa(e.StatusCode)
}

// ClientOptions configures one verified HTTPS relay. BearerToken authenticates
// a private relay over TLS and must be empty or 64 hexadecimal characters.
// RootCAs optionally replaces the system trust roots.
// Timeout bounds the entire HTTP request; zero uses eight seconds.
//
// BootstrapIP optionally fixes the relay's connection address without changing
// the HTTPS hostname, certificate verification, or TLS SNI. Without it, a
// hostname in the relay URL is looked up using the host's resolver before
// connecting. Use an explicit bootstrap address when that lookup could depend
// on the relay itself, or when no DNS lookup outside the relay is acceptable.
type ClientOptions struct {
	BearerToken string
	RootCAs     *x509.CertPool
	Timeout     time.Duration
	BootstrapIP netip.Addr
}

// Client is safe for concurrent use and sends DNS packets to one HTTPS relay.
// It never retries a query through another relay, a proxy, or a DNS resolver.
type Client struct {
	queryURL string
	token    string
	http     *http.Client
}

// NewClient uses baseURL plus /v1/query. baseURL must be an absolute HTTPS URL
// without user information, a query, or a fragment. An optional base path
// supports deployments behind a reverse proxy. TLS certificate verification
// is mandatory, and environment proxies and redirects are disabled.
func NewClient(baseURL string, options ClientOptions) (*Client, error) {
	u, err := clientURL(baseURL)
	if err != nil {
		return nil, err
	}
	if options.BearerToken != "" && !ValidToken(options.BearerToken) {
		return nil, ErrRelayToken
	}
	timeout := options.Timeout
	if timeout < 0 || timeout > clientMaxTimeout {
		return nil, ErrRelayTimeout
	}
	if timeout == 0 {
		timeout = clientTimeout
	}

	dialer := &net.Dialer{Timeout: 4 * time.Second, KeepAlive: 30 * time.Second}
	dial := dialer.DialContext
	if options.BootstrapIP.IsValid() {
		bootstrap := options.BootstrapIP.Unmap()
		if options.BootstrapIP.Zone() != "" || bootstrap.IsUnspecified() || bootstrap.IsMulticast() {
			return nil, ErrRelayBootstrap
		}
		port := u.Port()
		if port == "" {
			port = "443"
		}
		addr := net.JoinHostPort(bootstrap.String(), port)
		dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		}
	}
	var roots *x509.CertPool
	if options.RootCAs != nil {
		roots = options.RootCAs.Clone()
	}
	transport := &http.Transport{
		DialContext: dial,
		// With no Proxy function, no request or credential can reach a proxy
		// selected by the environment. The URL host supplies TLS SNI and name
		// verification even when DialContext uses a numeric bootstrap address.
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots},
		ForceAttemptHTTP2:      true,
		DisableCompression:     true,
		TLSHandshakeTimeout:    4 * time.Second,
		ResponseHeaderTimeout:  timeout,
		IdleConnTimeout:        time.Minute,
		MaxIdleConns:           8,
		MaxIdleConnsPerHost:    8,
		MaxConnsPerHost:        16,
		MaxResponseHeaderBytes: 8 << 10,
	}
	return &Client{
		queryURL: u.String(),
		token:    options.BearerToken,
		http: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func clientURL(baseURL string) (*url.URL, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Opaque != "" ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.ContainsAny(baseURL, "# \t\r\n") ||
		strings.ContainsAny(u.Host, "%\\") || strings.HasSuffix(u.Host, ":") ||
		u.RawPath != "" || strings.Contains(u.Path, "\\") {
		return nil, ErrRelayEndpoint
	}
	if port := u.Port(); port != "" {
		p, err := strconv.ParseUint(port, 10, 16)
		if err != nil || p == 0 {
			return nil, ErrRelayEndpoint
		}
	}
	for _, part := range strings.Split(u.Path, "/") {
		if part == "." || part == ".." {
			return nil, ErrRelayEndpoint
		}
	}
	u.Path = strings.TrimRight(u.Path, "/") + QueryPath
	return u, nil
}

// CloseIdleConnections releases idle connections. Active queries are not
// interrupted; cancel their contexts to stop them.
func (c *Client) CloseIdleConnections() {
	if c != nil && c.http != nil {
		c.http.CloseIdleConnections()
	}
}

// Query sends a DNS wire packet to the given target address, using either UDP
// or TCP between the relay and the target on port 53. The response remains a
// raw DNS message; the caller still has to apply its DNS/DNSSEC validation.
func (c *Client) Query(ctx context.Context, target netip.Addr, tcp bool, wire []byte) ([]byte, error) {
	if c == nil || c.http == nil {
		return nil, ErrRelayEndpoint
	}
	if ctx == nil {
		return nil, ErrRelayRequest
	}
	end, err := checkQuery(wire)
	if err != nil {
		return nil, ErrRelayRequest
	}
	if !publicAddress(target) {
		return nil, ErrRelayTarget
	}
	frame := make([]byte, 2, 2+target.BitLen()/8+len(wire))
	if tcp {
		frame[0] = 1
	}
	if target.Is4() {
		frame[1] = 4
		ip := target.As4()
		frame = append(frame, ip[:]...)
	} else {
		frame[1] = 6
		ip := target.As16()
		frame = append(frame, ip[:]...)
	}
	off := len(frame)
	frame = append(frame, wire...)
	p := packet{target: target, tcp: tcp, wire: frame[off:], end: end}
	limit := clientTCPLimit
	if !tcp {
		limit = udpLimit(p)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.queryURL, bytes.NewReader(frame))
	if err != nil {
		return nil, ErrRelayRequest
	}
	// Do not permit the transport or a redirect to replay the DNS packet.
	req.GetBody = nil
	req.Header.Set("Content-Type", MediaType)
	req.Header.Set("Accept", MediaType)
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("User-Agent", "")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, clientTransportError(ctx, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPStatusError{StatusCode: resp.StatusCode}
	}
	types := resp.Header.Values("Content-Type")
	encodings := resp.Header.Values("Content-Encoding")
	if len(types) != 1 || !strings.EqualFold(types[0], MediaType) ||
		(len(encodings) != 0 && (len(encodings) != 1 || !strings.EqualFold(encodings[0], "identity"))) ||
		resp.ContentLength > int64(limit) || (resp.ContentLength >= 0 && resp.ContentLength < int64(end)) {
		return nil, ErrRelayResponse
	}
	reply, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return nil, clientTransportError(ctx, err)
	}
	if len(reply) > limit || !responseMatches(p, reply) {
		return nil, ErrRelayResponse
	}
	return reply, nil
}

func clientTransportError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return context.DeadlineExceeded
	}
	// net/http errors can contain URLs, addresses or certificate details.
	return ErrRelayTransport
}
