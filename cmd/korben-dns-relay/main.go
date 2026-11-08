package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Korben00/korben-dns-relay/relay"
)

func main() {
	var err error
	if len(os.Args) < 2 {
		err = errors.New("usage: korben-dns-relay {serve|token|probe}")
	} else {
		switch os.Args[1] {
		case "token":
			if len(os.Args) != 2 {
				err = errors.New("token takes no arguments")
				break
			}
			var token [32]byte
			if _, err = rand.Read(token[:]); err == nil {
				_, err = fmt.Println(hex.EncodeToString(token[:]))
			}
		case "serve":
			err = serve(os.Args[2:])
		case "probe":
			err = probe(os.Args[2:])
		default:
			err = errors.New("usage: korben-dns-relay {serve|token|probe}")
		}
	}
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func readToken(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("token must be stored in a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return "", errors.New("restrict token file permissions to its owner")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("cannot open token file")
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 67))
	token := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	if err != nil || !relay.ValidToken(token) {
		return "", errors.New("invalid token file")
	}
	return token, nil
}

func serve(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := flags.String("listen", "127.0.0.1:8443", "numeric listener address and port")
	cert := flags.String("cert", "", "PEM certificate chain")
	key := flags.String("key", "", "PEM private key")
	tokenFile := flags.String("token-file", "", "file containing the private access token")
	allow := flags.String("allow", "", "comma-separated exact public destination IPs")
	deny := flags.String("deny", "", "comma-separated additional denied CIDRs")
	public := flags.Bool("public", false, "anonymous mode; requires an exact destination list")
	any := flags.Bool("allow-any-public", false, "allow any permitted public IP; authenticated private mode only")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *cert == "" || *key == "" || (*public && *tokenFile != "") {
		return errors.New("provide --cert and --key; public mode must not have a token file")
	}
	listen, err := netip.ParseAddrPort(*addr)
	if err != nil || listen.Port() == 0 {
		return errors.New("invalid numeric listener address or port")
	}
	token, err := readToken(*tokenFile)
	if err != nil {
		return err
	}
	cfg := relay.Config{Token: token, Public: *public, AnyPublicAuthority: *any}
	if *allow != "" {
		for _, value := range strings.Split(*allow, ",") {
			ip, err := netip.ParseAddr(strings.TrimSpace(value))
			if err != nil {
				return errors.New("invalid address in --allow")
			}
			cfg.Allow = append(cfg.Allow, ip)
		}
	}
	if *deny != "" {
		for _, value := range strings.Split(*deny, ",") {
			p, err := netip.ParsePrefix(strings.TrimSpace(value))
			if err != nil {
				return errors.New("invalid network in --deny")
			}
			cfg.Deny = append(cfg.Deny, p.Masked())
		}
	}
	handler, err := relay.NewServer(cfg)
	if err != nil {
		return err
	}
	pair, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		return errors.New("cannot load TLS certificate and key")
	}
	raw, err := net.Listen("tcp", listen.String())
	if err != nil {
		return errors.New("cannot bind HTTPS listener")
	}
	listener := &limitedListener{Listener: raw, slots: make(chan struct{}, 128), closed: make(chan struct{})}
	defer listener.Close()
	server := &http.Server{
		Handler: handler, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}},
		ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 25 * time.Second, MaxHeaderBytes: 4096,
		ErrorLog: log.New(io.Discard, "", 0),
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams:      8,
			MaxDecoderHeaderTableSize: 4096, MaxEncoderHeaderTableSize: 4096,
			MaxReadFrameSize: 16 << 10, MaxReceiveBufferPerStream: 16 << 10,
			MaxReceiveBufferPerConnection: 64 << 10,
			WriteByteTimeout:              5 * time.Second,
		},
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		deadline, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if server.Shutdown(deadline) != nil {
			_ = server.Close()
		}
	}()
	err = server.ServeTLS(listener, "", "")
	stop()
	<-done
	if !errors.Is(err, http.ErrServerClosed) {
		return errors.New("HTTPS listener stopped unexpectedly")
	}
	return nil
}

type limitedListener struct {
	net.Listener
	slots  chan struct{}
	closed chan struct{}
	once   sync.Once
}

func (l *limitedListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.closed:
		return nil, net.ErrClosed
	}
	conn, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitedConn{Conn: conn, release: func() { <-l.slots }}, nil
}

func (l *limitedListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return l.Listener.Close()
}

type limitedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func probe(args []string) error {
	flags := flag.NewFlagSet("probe", flag.ContinueOnError)
	endpoint := flags.String("url", "", "HTTPS base URL")
	bootstrap := flags.String("bootstrap-ip", "", "numeric relay IP, avoiding a DNS lookup")
	target := flags.String("target", "198.41.0.4", "numeric authoritative server IP")
	tokenFile := flags.String("token-file", "", "private token file, if required")
	tcp := flags.Bool("tcp", false, "use TCP from relay to authority")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	ip, err := netip.ParseAddr(*target)
	if err != nil {
		return errors.New("invalid authority address")
	}
	token, err := readToken(*tokenFile)
	if err != nil {
		return err
	}
	opts := relay.ClientOptions{BearerToken: token}
	if *bootstrap != "" {
		opts.BootstrapIP, err = netip.ParseAddr(*bootstrap)
		if err != nil {
			return errors.New("invalid bootstrap address")
		}
	}
	client, err := relay.NewClient(*endpoint, opts)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	// One non-recursive . NS query; deliberately no arbitrary input file.
	wire := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1}
	if _, err := rand.Read(wire[:2]); err != nil {
		return err
	}
	answer, err := client.Query(context.Background(), ip, *tcp, wire)
	if err != nil {
		return err
	}
	fmt.Printf("DNS response: %d bytes, rcode=%d, AA=%t, TC=%t\n",
		len(answer), answer[3]&15, answer[2]&4 != 0, answer[2]&2 != 0)
	return nil
}
