package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

const outboundDialTimeout = 10 * time.Second

type contextDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type outboundTransport struct {
	httpClient  *http.Client
	relayDialer contextDialer
}

type contextErrorDialer struct {
	dialer contextDialer
}

func (d contextErrorDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.dialer.DialContext(ctx, network, address)
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return conn, err
}

var (
	processSOCKS5AuthOnce sync.Once
	processSOCKS5Auth     *proxy.Auth
	processSOCKS5AuthErr  error
)

func validateOutboundMode(wireguard bool, socks5Address string) error {
	if wireguard && socks5Address != "" {
		return errors.New("SOCKS5 cannot proxy the WireGuard UDP data plane")
	}
	return nil
}

func newOutboundTransport(socks5Address string) (*outboundTransport, error) {
	direct := &net.Dialer{Timeout: outboundDialTimeout, KeepAlive: 30 * time.Second}
	dialer := contextDialer(direct)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = direct.DialContext

	if socks5Address != "" {
		if err := validateSOCKS5Address(socks5Address); err != nil {
			return nil, err
		}
		auth, err := socks5IsolationAuth()
		if err != nil {
			return nil, err
		}
		proxyDialer, err := proxy.SOCKS5("tcp", socks5Address, auth, direct)
		if err != nil {
			return nil, fmt.Errorf("configure SOCKS5 proxy: %w", err)
		}
		contextProxyDialer, ok := proxyDialer.(proxy.ContextDialer)
		if !ok {
			return nil, errors.New("SOCKS5 dialer does not support contexts")
		}
		dialer = contextErrorDialer{dialer: contextProxyDialer}
		transport.Proxy = nil
		transport.DialContext = dialer.DialContext
	}

	return &outboundTransport{
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   bootstrapTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		relayDialer: dialer,
	}, nil
}

func validateSOCKS5Address(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return fmt.Errorf("invalid SOCKS5 address %q: expected host:port", address)
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return fmt.Errorf("invalid SOCKS5 address %q: port must be within 1-65535", address)
	}
	return nil
}

func socks5IsolationAuth() (*proxy.Auth, error) {
	processSOCKS5AuthOnce.Do(func() {
		credential := make([]byte, 32)
		if _, err := rand.Read(credential); err != nil {
			processSOCKS5AuthErr = fmt.Errorf("generate SOCKS5 isolation credentials: %w", err)
			return
		}
		processSOCKS5Auth = &proxy.Auth{
			User:     base64.RawURLEncoding.EncodeToString(credential[:16]),
			Password: base64.RawURLEncoding.EncodeToString(credential[16:]),
		}
	})
	return processSOCKS5Auth, processSOCKS5AuthErr
}
