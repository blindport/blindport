package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"log/slog"

	"github.com/blindport/blindport/internal/protocol"
	"github.com/blindport/blindport/internal/relayauth"
	"github.com/blindport/blindport/internal/sniproxy"
	"github.com/blindport/blindport/internal/tunnel"
	"github.com/blindport/blindport/internal/wgnet"
)

type tokenResolver interface {
	Resolve(context.Context, string) (*relayauth.Resolution, error)
}

// relay is the runtime state of a relay node.
type relay struct {
	log                 *slog.Logger
	shutdown            context.CancelFunc
	resolver            tokenResolver
	listenIPs           []string
	listenPorts         []string
	sharedIPs           []string
	sharedTCPPorts      []uint16
	sharedUDPPorts      []uint16
	tlsConfig           *tls.Config // mTLS config for control plane; nil disables mTLS
	reauthInterval      time.Duration
	reauthMaxStale      time.Duration
	sniEnabled          bool
	challengeEnabled    bool
	limits              *admissionLimits
	metrics             *relayMetrics
	handlers            handlerTracker
	shutdownTimeout     time.Duration
	maxStreamsPerTunnel int
	udpAssociationIdle  time.Duration
	// tunnels keyed by claim, e.g. "ip:203.0.113.10" or "domain:alice.example.com"
	mu         sync.RWMutex
	tunnels    map[string]*tunnel.Conn
	allTunnels map[*tunnel.Conn]struct{}
}

func main() {
	control := flag.String("control", ":5443", "control plane listen address")
	extraControlListeners := flag.String("control-listeners", os.Getenv("BLINDPORT_RELAY_CONTROL_LISTENERS"), "comma-separated additional control plane listen addresses")
	backendURL := flag.String("backend", envDefault("BLINDPORT_BACKEND_URL", "http://localhost:8000"), "backend base URL")
	secret := flag.String("secret", os.Getenv("BLINDPORT_RELAY_SECRET"), "backend relay secret (X-Relay-Secret)")
	listenIPs := flag.String("ips", os.Getenv("BLINDPORT_RELAY_IPS"), "comma-separated public IPs to bind for Blindport IP")
	listenPorts := flag.String("ports", envDefault("BLINDPORT_RELAY_PORTS", "80,443"), "comma-separated ports to forward")
	sharedIPs := flag.String("shared-ips", os.Getenv("BLINDPORT_RELAY_SHARED_IPS"), "comma-separated shared ingress IPs for Blindport Port")
	sharedTCPPorts := flag.String("shared-ports", os.Getenv("BLINDPORT_RELAY_SHARED_TCP_PORTS"), "inclusive Blindport Port TCP range, for example 10000-10007")
	sharedUDPPorts := flag.String("shared-udp-ports", os.Getenv("BLINDPORT_RELAY_SHARED_UDP_PORTS"), "inclusive Blindport Port UDP range, for example 10000-10007")
	sniListen := flag.String("sni", envDefault("BLINDPORT_RELAY_SNI", ":4443"), "shared-pool SNI listen address (set empty to disable)")
	challengeListen := flag.String("http-challenge", os.Getenv("BLINDPORT_RELAY_HTTP_CHALLENGE"), "HTTP listen address for HTTPS redirects and HTTP-01 forwarding, for example :80 (empty disables it; safe behind an L7 frontend)")
	mtlsHosts := flag.String("mtls-hosts", os.Getenv("BLINDPORT_RELAY_MTLS_HOSTS"), "comma-separated SAN hostnames for the relay server cert")
	disableMTLS := flag.Bool("disable-mtls", os.Getenv("BLINDPORT_RELAY_DISABLE_MTLS") == "1", "disable mTLS on the control plane (insecure, dev only)")
	reauthInterval := flag.Duration("reauth-interval", envDurationDefault("BLINDPORT_RELAY_REAUTH_INTERVAL", 45*time.Second), "established tunnel reauthorization interval")
	reauthMaxStale := flag.Duration("reauth-max-staleness", envDurationDefault("BLINDPORT_RELAY_REAUTH_MAX_STALENESS", 90*time.Second), "maximum time an established tunnel may retain authorization during resolver errors")
	adminAddr := flag.String("admin", envDefault("BLINDPORT_RELAY_ADMIN", "127.0.0.1:9090"), "private health and metrics listen address")
	maxControl := flag.Int("max-control-handshakes", envIntDefault("BLINDPORT_RELAY_MAX_CONTROL_HANDSHAKES", 256), "maximum concurrent control handshakes")
	maxIngress := flag.Int("max-ingress", envIntDefault("BLINDPORT_RELAY_MAX_INGRESS", 4096), "maximum concurrent public ingress connections")
	maxSNI := flag.Int("max-sni-peeks", envIntDefault("BLINDPORT_RELAY_MAX_SNI_PEEKS", 512), "maximum concurrent SNI ClientHello inspections")
	maxChallenges := flag.Int("max-http-challenges", envIntDefault("BLINDPORT_RELAY_MAX_HTTP_CHALLENGES", 64), "maximum concurrent HTTP redirect and HTTP-01 requests")
	challengeRate := flag.Int("http-challenge-rate", envIntDefault("BLINDPORT_RELAY_HTTP_CHALLENGE_RATE", 600), "valid HTTP redirect and HTTP-01 requests allowed per minute per direct peer (requests behind one L7 frontend share its allowance)")
	challengeBurst := flag.Int("http-challenge-burst", envIntDefault("BLINDPORT_RELAY_HTTP_CHALLENGE_BURST", 100), "HTTP redirect and HTTP-01 per-peer burst allowance")
	maxControlSource := flag.Int("max-control-per-source", envIntDefault("BLINDPORT_RELAY_MAX_CONTROL_PER_SOURCE", 8), "maximum concurrent control handshakes per direct peer")
	maxIngressSource := flag.Int("max-ingress-per-source", envIntDefault("BLINDPORT_RELAY_MAX_INGRESS_PER_SOURCE", 128), "maximum concurrent ingress connections per direct peer")
	shutdownTimeout := flag.Duration("shutdown-timeout", envDurationDefault("BLINDPORT_RELAY_SHUTDOWN_TIMEOUT", 15*time.Second), "maximum handler drain time during shutdown")
	certMargin := flag.Duration("certificate-ready-margin", envDurationDefault("BLINDPORT_RELAY_CERT_READY_MARGIN", 5*time.Minute), "certificate lifetime required for readiness")
	maxStreamsPerTunnel := flag.Int("max-streams-per-tunnel", envIntDefault("BLINDPORT_RELAY_MAX_STREAMS_PER_TUNNEL", 256), "maximum concurrent streams on one client tunnel")
	udpAssociationIdle := flag.Duration("udp-association-idle", envDurationDefault("BLINDPORT_RELAY_UDP_ASSOCIATION_IDLE", 2*time.Minute), "UDP source association idle timeout")
	wireguardEnabled := flag.Bool("wireguard", os.Getenv("BLINDPORT_RELAY_WIREGUARD") == "1", "enable the routed WireGuard Blindport IP plane (Linux only)")
	wireguardInterface := flag.String("wireguard-interface", envDefault("BLINDPORT_RELAY_WIREGUARD_INTERFACE", "bpwg0"), "routed WireGuard interface name")
	wireguardPort := flag.Int("wireguard-port", envIntDefault("BLINDPORT_RELAY_WIREGUARD_PORT", 51820), "routed WireGuard UDP listen port")
	wireguardKeyFile := flag.String("wireguard-key-file", os.Getenv("BLINDPORT_RELAY_WIREGUARD_KEY_FILE"), "persistent relay WireGuard private key file")
	wireguardMTU := flag.Int("wireguard-mtu", envIntDefault("BLINDPORT_RELAY_WIREGUARD_MTU", 1420), "routed WireGuard interface MTU")
	wireguardInterval := flag.Duration("wireguard-interval", envDurationDefault("BLINDPORT_RELAY_WIREGUARD_INTERVAL", 10*time.Second), "routed desired-state reconcile interval")
	wireguardMaxStale := flag.Duration("wireguard-max-staleness", envDurationDefault("BLINDPORT_RELAY_WIREGUARD_MAX_STALENESS", 90*time.Second), "maximum backend staleness before the routed plane fails closed")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if *secret == "" {
		logger.Error("missing BLINDPORT_RELAY_SECRET / -secret")
		os.Exit(2)
	}
	if err := validateReauthorizationConfig(*reauthInterval, *reauthMaxStale); err != nil {
		logger.Error("invalid reauthorization configuration", "err", err)
		os.Exit(2)
	}
	parsedConfig, err := parseRelayConfig(*listenIPs, *listenPorts, *sharedIPs, *sharedTCPPorts, *sharedUDPPorts)
	if err != nil {
		logger.Error("invalid relay listener configuration", "err", err)
		os.Exit(2)
	}
	controlAddrs, err := parseControlListeners(*control, *extraControlListeners)
	if err != nil {
		logger.Error("invalid control listener configuration", "err", err)
		os.Exit(2)
	}

	limiters, err := newAdmissionLimits(limitConfig{
		controlHandshakes: *maxControl, totalIngress: *maxIngress, sniPeeks: *maxSNI, challenges: *maxChallenges,
		controlPerSource: *maxControlSource, ingressPerSource: *maxIngressSource,
		challengeRate: *challengeRate, challengeBurst: *challengeBurst,
	})
	if err != nil {
		logger.Error("invalid relay concurrency limits", "err", err)
		os.Exit(2)
	}
	if *shutdownTimeout <= 0 || *shutdownTimeout > 5*time.Minute || *certMargin <= 0 || *maxStreamsPerTunnel <= 0 || *maxStreamsPerTunnel > tunnel.MaxConcurrentStreams || *udpAssociationIdle < time.Second || *udpAssociationIdle > time.Hour {
		logger.Error("invalid shutdown or certificate readiness duration")
		os.Exit(2)
	}
	resolver, err := relayauth.New(*backendURL, *secret)
	if err != nil {
		logger.Error("invalid backend configuration", "err", err)
		os.Exit(2)
	}
	health := newRelayHealth(!*disableMTLS, *certMargin, *reauthMaxStale)
	metrics := &relayMetrics{health: health}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	r := &relay{
		log:                 logger,
		shutdown:            cancel,
		resolver:            resolver,
		listenIPs:           parsedConfig.dedicatedIPs,
		listenPorts:         parsedConfig.dedicatedPorts,
		sharedIPs:           parsedConfig.sharedIPs,
		sharedTCPPorts:      parsedConfig.sharedTCPPorts,
		sharedUDPPorts:      parsedConfig.sharedUDPPorts,
		reauthInterval:      *reauthInterval,
		reauthMaxStale:      *reauthMaxStale,
		sniEnabled:          *sniListen != "",
		challengeEnabled:    *challengeListen != "",
		limits:              limiters,
		metrics:             metrics,
		shutdownTimeout:     *shutdownTimeout,
		maxStreamsPerTunnel: *maxStreamsPerTunnel,
		udpAssociationIdle:  *udpAssociationIdle,
		tunnels:             map[string]*tunnel.Conn{},
		allTunnels:          map[*tunnel.Conn]struct{}{},
	}

	var wireguardDone <-chan struct{}
	if *wireguardEnabled {
		if err := validateWireGuardConfig(*wireguardInterval, *wireguardMaxStale, *wireguardMTU, *wireguardPort); err != nil {
			logger.Error("invalid WireGuard configuration", "err", err)
			os.Exit(2)
		}
		wireguardKey, err := loadRelayWireGuardKey(*wireguardKeyFile, os.Getenv("BLINDPORT_RELAY_WIREGUARD_KEY"))
		if err != nil {
			logger.Error("load WireGuard key", "err", err)
			os.Exit(1)
		}
		if err := wgnet.EnsureDevice(*wireguardInterface, *wireguardMTU); err != nil {
			logger.Error("prepare WireGuard device", "err", err)
			os.Exit(1)
		}
		if err := wgnet.ConfigureRelayDevice(*wireguardInterface, wireguardKey, *wireguardPort); err != nil {
			logger.Error("configure WireGuard device", "err", err)
			os.Exit(1)
		}
		dataplane, err := wgnet.NewLinuxRelayDataplane(*wireguardInterface)
		if err != nil {
			logger.Error("bind WireGuard dataplane", "err", err)
			os.Exit(1)
		}
		health.wgNeeded.Store(true)
		manager := newWireGuardManager(
			logger, resolver, wgnet.NewReconciler(dataplane),
			*wireguardInterval, *wireguardMaxStale, health, metrics,
		)
		done := make(chan struct{})
		wireguardDone = done
		go func() {
			defer close(done)
			manager.run(ctx)
		}()
		logger.Info("routed WireGuard plane enabled",
			"interface", *wireguardInterface,
			"listen_port", *wireguardPort,
			"public_key", wireguardKey.PublicKey().String())
	}

	var certificateCredentials *certificateManager
	if !*disableMTLS {
		certIPs := append(append([]string{}, r.listenIPs...), r.sharedIPs...)
		certificateCredentials, err = newCertificateManager(ctx, resolver, splitNonEmpty(*mtlsHosts, ","), certIPs, health, logger)
		if err != nil {
			logger.Error("mTLS setup failed", "err", err)
			os.Exit(1)
		}
		r.tlsConfig = certificateCredentials.tlsConfig()
		go certificateCredentials.run(ctx)
		logger.Info("mTLS enabled on control plane")
	} else {
		health.observeAuth(nil)
		logger.Warn("mTLS DISABLED on control plane (BLINDPORT_RELAY_DISABLE_MTLS=1)")
	}

	listeners, err := bindRelayListeners(controlAddrs, *sniListen, *challengeListen, parsedConfig)
	if err != nil {
		logger.Error("relay listener setup failed", "err", err)
		os.Exit(1)
	}
	adminListener, err := net.Listen("tcp", *adminAddr)
	if err != nil {
		closeBoundListeners(listeners)
		logger.Error("relay admin listener setup failed", "err", err)
		os.Exit(1)
	}
	adminServer := &http.Server{
		Handler: metrics.handler(), ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10,
	}
	go func() {
		if err := adminServer.Serve(adminListener); err != nil && err != http.ErrServerClosed {
			logger.Error("relay admin server failed", "err", err)
			health.listenersUp.Store(false)
			cancel()
		}
	}()
	for _, bound := range listeners {
		switch bound.kind {
		case listenerControl:
			go r.serveControl(ctx, bound.listener)
		case listenerDedicated:
			go r.serveDedicatedIP(ctx, bound.listener, bound.ip, strconv.Itoa(int(bound.port)))
		case listenerPort:
			if bound.packetConn != nil {
				go r.serveUDPPort(ctx, bound.packetConn, bound.ip, bound.port)
			} else {
				go r.servePort(ctx, bound.listener, bound.ip, bound.port)
			}
		case listenerSNI:
			go r.serveSNIPool(ctx, bound.listener)
		case listenerChallenge:
			go r.serveHTTPChallenges(ctx, bound.listener)
		}
	}
	health.listenersUp.Store(true)

	<-ctx.Done()
	health.draining.Store(true)
	health.listenersUp.Store(false)
	if wireguardDone != nil {
		<-wireguardDone
	}
	closeBoundListeners(listeners)
	r.closeAllTunnels()
	if !r.handlers.stopAndWait(r.shutdownTimeout) {
		logger.Warn("relay handler shutdown timed out")
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = adminServer.Shutdown(shutdownCtx)
	logger.Info("relay shutting down")
}

func (r *relay) serveControl(ctx context.Context, rawLn net.Listener) {
	var ln net.Listener = rawLn
	if r.tlsConfig != nil {
		ln = tls.NewListener(rawLn, r.tlsConfig)
	}
	r.log.Info("control plane listening", "mtls", r.tlsConfig != nil)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			r.listenerFailed("control", err)
			return
		}
		r.startControlHandler(ctx, conn)
	}
}

func (r *relay) startControlHandler(ctx context.Context, conn net.Conn) {
	index := int(listenerControl)
	r.metrics.connections[index].accepted.Add(1)
	releaseSource, ok := r.limits.controlSources.acquire(conn.RemoteAddr())
	if !ok {
		r.metrics.connections[index].rejected.Add(1)
		_ = conn.Close()
		return
	}
	releaseSlot, ok := tryAcquire(r.limits.handshakes)
	if !ok {
		releaseSource()
		r.metrics.connections[index].rejected.Add(1)
		_ = conn.Close()
		return
	}
	r.metrics.connections[index].active.Add(1)
	if !r.handlers.start(func() {
		var releaseOnce sync.Once
		releaseAdmission := func() {
			releaseOnce.Do(func() {
				releaseSource()
				releaseSlot()
			})
		}
		defer releaseAdmission()
		defer r.metrics.connections[index].active.Add(-1)
		r.handleControlConnWithAdmission(ctx, conn, releaseAdmission)
	}) {
		releaseSource()
		releaseSlot()
		r.metrics.connections[index].active.Add(-1)
		r.metrics.connections[index].rejected.Add(1)
		_ = conn.Close()
	}
}

func (r *relay) handleControlConn(ctx context.Context, conn net.Conn) {
	r.handleControlConnWithAdmission(ctx, conn, func() {})
}

func (r *relay) handleControlConnWithAdmission(ctx context.Context, conn net.Conn, handshakeComplete func()) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	hello, err := protocol.ReadFrameWithLimit(conn, protocol.MaxHelloFrameSize)
	if err != nil {
		r.metrics.control[controlBadHello].Add(1)
		r.log.Warn("invalid control hello")
		_ = conn.Close()
		return
	}
	if hello.Type != protocol.TypeHello || hello.Token == "" || len(hello.Token) > 512 || protocol.ValidateClaim(hello.Claim) != nil || protocol.ValidateVersion(hello.Version, hello.Claim) != nil {
		r.metrics.control[controlBadHello].Add(1)
		r.writeErr(conn, "bad hello")
		return
	}
	if !r.servesClaim(hello.Claim) {
		r.metrics.control[controlInventoryDenied].Add(1)
		r.writeErr(conn, "claim not served by this relay")
		return
	}
	res, err := r.resolver.Resolve(ctx, hello.Token)
	r.metrics.observeAuth(err)
	if err != nil {
		if relayauth.IsKind(err, relayauth.ErrorDenied) {
			r.metrics.control[controlAuthDenied].Add(1)
		} else {
			r.metrics.control[controlAuthError].Add(1)
		}
		r.log.Warn("control authorization failed")
		r.writeErr(conn, "invalid token")
		return
	}
	var peerIdentity *clientIdentity
	if r.tlsConfig != nil {
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			r.metrics.control[controlIdentityDenied].Add(1)
			r.log.Warn("mTLS connection has unexpected type", "type", fmt.Sprintf("%T", conn))
			r.writeErr(conn, "peer certificate identity unavailable")
			return
		}
		identity, err := requireCertificateIdentity(tlsConn.ConnectionState(), res)
		if err != nil {
			r.metrics.control[controlIdentityDenied].Add(1)
			r.log.Warn("peer certificate identity rejected")
			r.writeErr(conn, "peer certificate identity does not match token")
			return
		}
		peerIdentity = &identity
	}
	key := claimKey(hello.Claim)
	if !claimAllowed(res, hello.Claim) {
		r.metrics.control[controlAuthDenied].Add(1)
		r.writeErr(conn, "claim not authorized for token")
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	if err := protocol.WriteFrame(conn, &protocol.Frame{Type: protocol.TypeHelloOK, Version: protocol.CurrentVersion}); err != nil {
		r.metrics.control[controlWriteError].Add(1)
		_ = conn.Close()
		return
	}
	t, err := tunnel.NewWithStreamLimit(conn, nil, r.maxStreamsPerTunnel)
	if err != nil {
		r.metrics.control[controlWriteError].Add(1)
		return
	}
	t.SetUDPDropHandler(func() { r.metrics.udp.dropped.Add(1) })
	handshakeComplete()
	r.registerTunnel(key, hello.Claim.Kind, t)
	defer r.unregisterTunnel(key, hello.Claim.Kind, t)
	r.metrics.control[controlAccepted].Add(1)
	r.log.Info("client connected", "claim_kind", hello.Claim.Kind)
	sessionCtx, cancel := context.WithCancel(ctx)
	reauthDone := make(chan struct{})
	go r.watchAuthorization(sessionCtx, hello.Token, hello.Claim, peerIdentity, t, reauthDone)
	if err := t.Run(); err != nil {
		r.log.Info("client disconnected", "claim_kind", hello.Claim.Kind)
	}
	cancel()
	<-reauthDone
}

func (r *relay) writeErr(conn net.Conn, msg string) {
	_ = protocol.WriteFrame(conn, &protocol.Frame{Type: protocol.TypeHelloErr, Msg: msg})
	_ = conn.Close()
}

func (r *relay) registerTunnel(key string, kind protocol.ClaimKind, t *tunnel.Conn) {
	r.mu.Lock()
	old := r.tunnels[key]
	r.tunnels[key] = t
	r.allTunnels[t] = struct{}{}
	r.mu.Unlock()
	index := claimKindIndex(kind)
	r.metrics.tunnels[index].active.Add(1)
	r.metrics.tunnels[index].total.Add(1)
	if old != nil {
		_ = old.Close()
	}
}

func (r *relay) unregisterTunnel(key string, kind protocol.ClaimKind, t *tunnel.Conn) {
	r.mu.Lock()
	if cur, ok := r.tunnels[key]; ok && cur == t {
		delete(r.tunnels, key)
	}
	if _, ok := r.allTunnels[t]; ok {
		delete(r.allTunnels, t)
		r.metrics.tunnels[claimKindIndex(kind)].active.Add(-1)
	}
	r.mu.Unlock()
}

func (r *relay) getTunnel(key string) *tunnel.Conn {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.tunnels[key]
}

func (r *relay) closeAllTunnels() {
	r.mu.RLock()
	connections := make([]*tunnel.Conn, 0, len(r.allTunnels))
	for connection := range r.allTunnels {
		connections = append(connections, connection)
	}
	r.mu.RUnlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
}

func (r *relay) servesClaim(claim *protocol.Claim) bool {
	switch claim.Kind {
	case protocol.ClaimIP:
		for _, ip := range r.listenIPs {
			if ip == claim.IP {
				return true
			}
		}
	case protocol.ClaimPort:
		ipFound := false
		for _, ip := range r.sharedIPs {
			ipFound = ipFound || ip == claim.IP
		}
		if !ipFound {
			return false
		}
		ports := r.sharedTCPPorts
		if claim.Transport == protocol.TransportUDP {
			ports = r.sharedUDPPorts
		}
		for _, port := range ports {
			if port == claim.Port {
				return true
			}
		}
	case protocol.ClaimRelay:
		return r.sniEnabled || r.challengeEnabled
	}
	return false
}

func claimKey(c *protocol.Claim) string {
	switch c.Kind {
	case protocol.ClaimIP:
		return "ip:" + c.IP
	case protocol.ClaimPort:
		return "port:" + string(c.Transport) + ":" + net.JoinHostPort(c.IP, strconv.Itoa(int(c.Port)))
	case protocol.ClaimRelay:
		return "domain:" + strings.ToLower(c.Domain)
	}
	return ""
}

func claimAllowed(res *relayauth.Resolution, c *protocol.Claim) bool {
	switch c.Kind {
	case protocol.ClaimIP:
		for _, ip := range res.IPs {
			if ip == c.IP {
				return true
			}
		}
	case protocol.ClaimPort:
		for _, lease := range res.PortLeases {
			if lease.AssignedIP == c.IP && lease.AssignedPort == c.Port && lease.Transport == string(c.Transport) {
				return true
			}
		}
	case protocol.ClaimRelay:
		want := strings.ToLower(c.Domain)
		for _, d := range res.RelayDomains {
			if strings.ToLower(d) == want {
				return true
			}
		}
	}
	return false
}

type clientIdentityKind uint8

const (
	clientIdentityAccount clientIdentityKind = iota + 1
	clientIdentityUser
)

type clientIdentity struct {
	kind      clientIdentityKind
	accountID [16]byte
	userID    int64
}

func certificateIdentity(state tls.ConnectionState) (clientIdentity, error) {
	if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return clientIdentity{}, fmt.Errorf("no verified peer certificate")
	}
	cn := state.VerifiedChains[0][0].Subject.CommonName
	if strings.HasPrefix(cn, "account:") {
		accountID, err := parseCanonicalUUID(strings.TrimPrefix(cn, "account:"))
		if err != nil {
			return clientIdentity{}, fmt.Errorf("common name has a malformed account identity: %w", err)
		}
		return clientIdentity{kind: clientIdentityAccount, accountID: accountID}, nil
	}
	if !strings.HasPrefix(cn, "user:") {
		return clientIdentity{}, fmt.Errorf("common name %q is not a supported client identity", cn)
	}
	rawID := strings.TrimPrefix(cn, "user:")
	userID, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || userID <= 0 || strconv.FormatInt(userID, 10) != rawID {
		return clientIdentity{}, fmt.Errorf("common name %q has a malformed user identity", cn)
	}
	return clientIdentity{kind: clientIdentityUser, userID: userID}, nil
}

func requireCertificateIdentity(state tls.ConnectionState, resolution *relayauth.Resolution) (clientIdentity, error) {
	identity, err := certificateIdentity(state)
	if err != nil {
		return clientIdentity{}, err
	}
	if !identity.matchesResolution(resolution) {
		return clientIdentity{}, fmt.Errorf("certificate %s identity does not match resolved identity", identity.kindName())
	}
	return identity, nil
}

func (i clientIdentity) matchesResolution(resolution *relayauth.Resolution) bool {
	if resolution == nil {
		return false
	}
	switch i.kind {
	case clientIdentityAccount:
		accountID, err := parseCanonicalUUID(resolution.AccountID)
		return err == nil && accountID == i.accountID
	case clientIdentityUser:
		return resolution.UserID > 0 && resolution.UserID == i.userID
	default:
		return false
	}
}

func (i clientIdentity) kindName() string {
	if i.kind == clientIdentityAccount {
		return "account"
	}
	return "user"
}

func parseCanonicalUUID(value string) ([16]byte, error) {
	var parsed [16]byte
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return parsed, fmt.Errorf("UUID must use 8-4-4-4-12 format")
	}
	byteIndex := 0
	high := byte(0)
	for index := 0; index < len(value); index++ {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		digit := value[index]
		var nibble byte
		switch {
		case digit >= '0' && digit <= '9':
			nibble = digit - '0'
		case digit >= 'a' && digit <= 'f':
			nibble = digit - 'a' + 10
		default:
			return [16]byte{}, fmt.Errorf("UUID must contain lowercase hexadecimal digits")
		}
		if byteIndex%2 == 0 {
			high = nibble << 4
		} else {
			parsed[byteIndex/2] = high | nibble
		}
		byteIndex++
	}
	return parsed, nil
}

func validateReauthorizationConfig(interval, maxStaleness time.Duration) error {
	if interval <= 0 {
		return fmt.Errorf("reauthorization interval must be positive")
	}
	if maxStaleness < interval {
		return fmt.Errorf("maximum reauthorization staleness %s must be at least one interval %s", maxStaleness, interval)
	}
	return nil
}

func reauthorizationRequiresClose(res *relayauth.Resolution, err error, claim *protocol.Claim, peerIdentity *clientIdentity, lastAuthorized, now time.Time, maxStaleness time.Duration) bool {
	if err != nil {
		if relayauth.IsKind(err, relayauth.ErrorDenied) || relayauth.IsKind(err, relayauth.ErrorSecret) {
			return true
		}
		return !now.Before(lastAuthorized.Add(maxStaleness))
	}
	if res == nil || !claimAllowed(res, claim) {
		return true
	}
	return peerIdentity != nil && !peerIdentity.matchesResolution(res)
}

func (r *relay) watchAuthorization(ctx context.Context, token string, claim *protocol.Claim, peerIdentity *clientIdentity, t *tunnel.Conn, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(r.reauthInterval)
	defer ticker.Stop()
	lastAuthorized := time.Now()

	for {
		select {
		case <-ctx.Done():
			_ = t.Close()
			return
		case <-ticker.C:
			res, err := r.resolver.Resolve(ctx, token)
			r.metrics.observeAuth(err)
			now := time.Now()
			if reauthorizationRequiresClose(res, err, claim, peerIdentity, lastAuthorized, now, r.reauthMaxStale) {
				if err != nil {
					r.log.Warn("tunnel authorization became stale", "claim_kind", claim.Kind)
				} else {
					r.log.Info("tunnel no longer authorized", "claim_kind", claim.Kind)
				}
				_ = t.Close()
				return
			}
			if err != nil {
				r.log.Warn("tunnel reauthorization failed; retaining session", "claim_kind", claim.Kind)
				continue
			}
			lastAuthorized = now
			if res == nil {
				r.log.Info("tunnel no longer authorized", "claim_kind", claim.Kind)
				_ = t.Close()
				return
			}
		}
	}
}

func (r *relay) serveDedicatedIP(ctx context.Context, ln net.Listener, ip, port string) {
	r.log.Info("dedicated IP listener ready")
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			r.listenerFailed("ip", err)
			return
		}
		r.startIngressHandler(listenerDedicated, conn, func() {
			r.forwardTo(conn, "ip:"+ip, port)
		})
	}
}

func (r *relay) servePort(ctx context.Context, ln net.Listener, ip string, port uint16) {
	addr := net.JoinHostPort(ip, strconv.Itoa(int(port)))
	key := "port:" + string(protocol.TransportTCP) + ":" + addr
	r.log.Info("shared TCP port listener ready")
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			r.listenerFailed("port", err)
			return
		}
		r.startIngressHandler(listenerPort, conn, func() {
			r.forwardTo(conn, key, strconv.Itoa(int(port)))
		})
	}
}

func (r *relay) serveSNIPool(ctx context.Context, ln net.Listener) {
	r.log.Info("SNI pool listener ready")
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			r.listenerFailed("sni", err)
			return
		}
		r.startIngressHandler(listenerSNI, conn, func() { r.handleSNIConn(conn) })
	}
}

func (r *relay) listenerFailed(listener string, _ error) {
	r.metrics.health.listenersUp.Store(false)
	r.log.Error("relay listener failed", "listener", listener)
	if r.shutdown != nil {
		r.shutdown()
	}
}

func (r *relay) startIngressHandler(kind listenerKind, conn net.Conn, handler func()) {
	index := int(kind)
	r.metrics.connections[index].accepted.Add(1)
	releaseSource, ok := r.limits.ingressSources.acquire(conn.RemoteAddr())
	if !ok {
		r.metrics.connections[index].rejected.Add(1)
		_ = conn.Close()
		return
	}
	r.metrics.connections[index].active.Add(1)
	if !r.handlers.start(func() {
		defer releaseSource()
		defer r.metrics.connections[index].active.Add(-1)
		handler()
	}) {
		releaseSource()
		r.metrics.connections[index].active.Add(-1)
		r.metrics.connections[index].rejected.Add(1)
		_ = conn.Close()
	}
}

type relayListenerConfig struct {
	dedicatedIPs   []string
	dedicatedPorts []string
	sharedIPs      []string
	sharedTCPPorts []uint16
	sharedUDPPorts []uint16
}

func parseControlListeners(primary, extras string) ([]string, error) {
	primary = strings.TrimSpace(primary)
	if primary == "" {
		return nil, fmt.Errorf("primary control listener cannot be empty")
	}
	listeners := []string{primary}
	seen := map[string]struct{}{primary: {}}
	if extras == "" {
		return listeners, nil
	}
	for _, raw := range strings.Split(extras, ",") {
		addr := strings.TrimSpace(raw)
		if addr == "" {
			return nil, fmt.Errorf("additional control listeners contain an empty entry")
		}
		if _, exists := seen[addr]; exists {
			return nil, fmt.Errorf("duplicate control listener %q", addr)
		}
		seen[addr] = struct{}{}
		listeners = append(listeners, addr)
	}
	return listeners, nil
}

func parseRelayConfig(dedicatedIPs, dedicatedPorts, sharedIPs, sharedTCPPorts, sharedUDPPorts string) (relayListenerConfig, error) {
	var cfg relayListenerConfig
	var err error
	if cfg.dedicatedIPs, err = parseIPList(dedicatedIPs, "dedicated IPs"); err != nil {
		return cfg, err
	}
	if cfg.dedicatedPorts, err = parsePortList(dedicatedPorts); err != nil {
		return cfg, err
	}
	if cfg.sharedIPs, err = parseIPList(sharedIPs, "shared IPs"); err != nil {
		return cfg, err
	}
	if sharedTCPPorts != "" {
		if cfg.sharedTCPPorts, err = parsePortRange(sharedTCPPorts, "TCP"); err != nil {
			return cfg, err
		}
	}
	if sharedUDPPorts != "" {
		if cfg.sharedUDPPorts, err = parsePortRange(sharedUDPPorts, "UDP"); err != nil {
			return cfg, err
		}
	}
	if len(cfg.sharedIPs) == 0 && (len(cfg.sharedTCPPorts) != 0 || len(cfg.sharedUDPPorts) != 0) {
		return cfg, fmt.Errorf("shared port inventory requires shared IPs")
	}
	if len(cfg.sharedIPs) != 0 && len(cfg.sharedTCPPorts) == 0 && len(cfg.sharedUDPPorts) == 0 {
		return cfg, fmt.Errorf("shared IPs require TCP or UDP port inventory")
	}
	dedicated := make(map[string]struct{}, len(cfg.dedicatedIPs))
	for _, ip := range cfg.dedicatedIPs {
		dedicated[ip] = struct{}{}
	}
	for _, ip := range cfg.sharedIPs {
		if _, exists := dedicated[ip]; exists {
			return cfg, fmt.Errorf("IP %s appears in both dedicated and shared inventory", ip)
		}
	}
	return cfg, nil
}

func parseIPList(value, name string) ([]string, error) {
	if value == "" {
		return nil, nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0)
	for _, raw := range strings.Split(value, ",") {
		item := strings.TrimSpace(raw)
		parsed := net.ParseIP(item)
		if item == "" || parsed == nil {
			return nil, fmt.Errorf("%s contains invalid IP %q", name, item)
		}
		canonical := parsed.String()
		if _, exists := seen[canonical]; exists {
			return nil, fmt.Errorf("%s contains duplicate IP %s", name, canonical)
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	return out, nil
}

func parsePortList(value string) ([]string, error) {
	if value == "" {
		return nil, nil
	}
	seen := map[uint16]struct{}{}
	out := make([]string, 0)
	for _, raw := range strings.Split(value, ",") {
		item := strings.TrimSpace(raw)
		port, err := strconv.ParseUint(item, 10, 16)
		if err != nil || port == 0 {
			return nil, fmt.Errorf("invalid dedicated TCP port %q", item)
		}
		if _, exists := seen[uint16(port)]; exists {
			return nil, fmt.Errorf("duplicate dedicated TCP port %d", port)
		}
		seen[uint16(port)] = struct{}{}
		out = append(out, strconv.FormatUint(port, 10))
	}
	return out, nil
}

func parsePortRange(value, transport string) ([]uint16, error) {
	if value != strings.TrimSpace(value) || strings.Count(value, "-") != 1 {
		return nil, fmt.Errorf("shared %s ports must be one inclusive range such as 10000-10007", transport)
	}
	parts := strings.SplitN(value, "-", 2)
	start, startErr := strconv.ParseUint(parts[0], 10, 16)
	end, endErr := strconv.ParseUint(parts[1], 10, 16)
	if startErr != nil || endErr != nil || start == 0 || start > end {
		return nil, fmt.Errorf("invalid shared %s port range %q", transport, value)
	}
	if end-start+1 > 4096 {
		return nil, fmt.Errorf("shared %s port range cannot contain more than 4096 ports", transport)
	}
	out := make([]uint16, 0, end-start+1)
	for port := start; port <= end; port++ {
		out = append(out, uint16(port))
	}
	return out, nil
}

type listenerKind uint8

const (
	listenerControl listenerKind = iota
	listenerDedicated
	listenerPort
	listenerSNI
	listenerChallenge
)

type boundRelayListener struct {
	kind       listenerKind
	listener   net.Listener
	packetConn net.PacketConn
	ip         string
	port       uint16
}

func bindRelayListeners(controlAddrs []string, sniAddr, challengeAddr string, cfg relayListenerConfig) ([]boundRelayListener, error) {
	type spec struct {
		kind    listenerKind
		network string
		addr    string
		ip      string
		port    uint16
	}
	specs := make([]spec, 0, len(controlAddrs))
	for _, addr := range controlAddrs {
		specs = append(specs, spec{kind: listenerControl, addr: addr})
	}
	for _, ip := range cfg.dedicatedIPs {
		for _, rawPort := range cfg.dedicatedPorts {
			port, _ := strconv.ParseUint(rawPort, 10, 16)
			specs = append(specs, spec{kind: listenerDedicated, addr: net.JoinHostPort(ip, rawPort), ip: ip, port: uint16(port)})
		}
	}
	for _, ip := range cfg.sharedIPs {
		for _, port := range cfg.sharedTCPPorts {
			specs = append(specs, spec{kind: listenerPort, addr: net.JoinHostPort(ip, strconv.Itoa(int(port))), ip: ip, port: port})
		}
		for _, port := range cfg.sharedUDPPorts {
			specs = append(specs, spec{kind: listenerPort, addr: net.JoinHostPort(ip, strconv.Itoa(int(port))), ip: ip, port: port, network: "udp"})
		}
	}
	if sniAddr != "" {
		specs = append(specs, spec{kind: listenerSNI, addr: sniAddr})
	}
	if challengeAddr != "" {
		specs = append(specs, spec{kind: listenerChallenge, addr: challengeAddr})
	}

	bound := make([]boundRelayListener, 0, len(specs))
	for _, item := range specs {
		network := item.network
		if network == "" {
			network = "tcp"
		}
		var ln net.Listener
		var packetConn net.PacketConn
		var err error
		if network == "udp" {
			packetConn, err = net.ListenPacket(network, item.addr)
		} else {
			ln, err = net.Listen(network, item.addr)
		}
		if err != nil {
			closeBoundListeners(bound)
			return nil, fmt.Errorf("bind %s: %w", item.addr, err)
		}
		bound = append(bound, boundRelayListener{kind: item.kind, listener: ln, packetConn: packetConn, ip: item.ip, port: item.port})
	}
	return bound, nil
}

func closeBoundListeners(listeners []boundRelayListener) {
	for _, bound := range listeners {
		if bound.listener != nil {
			_ = bound.listener.Close()
		}
		if bound.packetConn != nil {
			_ = bound.packetConn.Close()
		}
	}
}

func (r *relay) handleSNIConn(conn net.Conn) {
	releasePeek, ok := tryAcquire(r.limits.sniPeeks)
	if !ok {
		r.metrics.connections[int(listenerSNI)].rejected.Add(1)
		_ = conn.Close()
		return
	}
	name, peeked, err := sniproxy.PeekSNI(conn, 5*time.Second)
	releasePeek()
	if err != nil {
		r.metrics.sni[sniInvalid].Add(1)
		r.log.Warn("invalid SNI ClientHello")
		_ = conn.Close()
		return
	}
	claim := &protocol.Claim{Kind: protocol.ClaimRelay, Domain: name}
	if protocol.ValidateClaim(claim) != nil {
		r.metrics.sni[sniInvalid].Add(1)
		_ = peeked.Close()
		return
	}
	if r.forwardTo(peeked, "domain:"+name, "443") {
		r.metrics.sni[sniSuccess].Add(1)
	} else {
		r.metrics.sni[sniNoTunnel].Add(1)
	}
}

func (r *relay) forwardTo(conn net.Conn, key, port string) bool {
	defer conn.Close()
	t := r.getTunnel(key)
	if t == nil {
		r.log.Info("no active tunnel for ingress")
		return false
	}
	src := conn.RemoteAddr().String()
	dst := key + ":" + port
	stream, err := t.OpenStream("tcp", src, dst)
	if err != nil {
		r.log.Warn("open ingress stream failed")
		return false
	}
	index := claimKindIndexFromKey(key)
	r.metrics.streams[index].active.Add(1)
	r.metrics.streams[index].total.Add(1)
	defer r.metrics.streams[index].active.Add(-1)
	type copyResult struct {
		direction int
		bytes     int64
	}
	done := make(chan copyResult, 2)
	go func() {
		copied, _ := io.Copy(stream, conn)
		done <- copyResult{direction: 0, bytes: copied}
	}()
	go func() {
		copied, _ := io.Copy(conn, stream)
		done <- copyResult{direction: 1, bytes: copied}
	}()
	first := <-done
	r.metrics.bytes[index][first.direction].Add(uint64(first.bytes))
	_ = conn.Close()
	_ = stream.Close()
	second := <-done
	r.metrics.bytes[index][second.direction].Add(uint64(second.bytes))
	return true
}

func claimKindIndexFromKey(key string) int {
	switch {
	case strings.HasPrefix(key, "ip:"):
		return claimKindIndex(protocol.ClaimIP)
	case strings.HasPrefix(key, "port:"):
		return claimKindIndex(protocol.ClaimPort)
	default:
		return claimKindIndex(protocol.ClaimRelay)
	}
}

func splitNonEmpty(s, sep string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, sep)
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDurationDefault(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid %s duration %q: %v\n", key, v, err)
		os.Exit(2)
	}
	return d
}

func envIntDefault(key string, def int) int {
	value := os.Getenv(key)
	if value == "" {
		return def
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid %s integer %q: %v\n", key, value, err)
		os.Exit(2)
	}
	return parsed
}
