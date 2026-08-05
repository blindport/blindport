package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/blindport/blindport/internal/protocol"
	"github.com/blindport/blindport/internal/tcpproxy"
	"github.com/blindport/blindport/internal/tunnel"
	"github.com/go-acme/lego/v4/lego"
)

const (
	bootstrapTimeout       = 10 * time.Second
	helloTimeout           = 10 * time.Second
	maxProvisioningJSON    = 1 << 20
	maxCertificateResponse = 256 << 10
)

var version = "dev"

// provisioning is one row from /api/v1/client/config.
type provisioning struct {
	RelayEndpoint  string   `json:"relay_endpoint"`
	RelayEndpoints []string `json:"relay_endpoints"`
	AssignedIP     string   `json:"assigned_ip,omitempty"`
	AssignedPort   uint16   `json:"assigned_port,omitempty"`
	Transport      string   `json:"transport"`
	Domain         string   `json:"domain,omitempty"`
	Product        string   `json:"product"`
	SubscriptionID string   `json:"subscription_id"`
}

type agentVersionResponse struct {
	Version string `json:"version"`
}

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	installUserServiceFlag := flag.Bool("install-user-service", false, "install and start the native user systemd service")
	tokenFlag := flag.String("token", "", "Blindport bearer token (or BLINDPORT_TOKEN env)")
	defaultTokenPath := defaultTokenFile()
	tokenFile := flag.String("token-file", defaultTokenPath, "file containing the token")
	backendURL := flag.String("backend", envDefault("BLINDPORT_BACKEND_URL", "https://blindport.com"), "backend base URL")
	relayOverride := flag.String("relay", os.Getenv("BLINDPORT_RELAY_CONTROL"), "override relay control address (host:port)")
	upstream := flag.String("upstream", os.Getenv("BLINDPORT_UPSTREAM"), "local upstream host:port (defaults to 127.0.0.1:443 for Relay, 127.0.0.1:80 otherwise)")
	httpChallengeUpstream := flag.String("http-challenge-upstream", os.Getenv("BLINDPORT_HTTP_CHALLENGE_UPSTREAM"), "optional Blindport Relay HTTP-01 upstream host:port; normal traffic remains on -upstream")
	claimKind := flag.String("kind", os.Getenv("BLINDPORT_KIND"), "ip, port, or relay (optional when exactly one framed subscription is active)")
	claimIP := flag.String("ip", os.Getenv("BLINDPORT_IP"), "Blindport IP or Blindport Port address to claim (defaults to first allocated)")
	claimPort := flag.String("port", os.Getenv("BLINDPORT_PORT"), "port number to claim (defaults to first allocated)")
	claimTransport := flag.String("transport", envDefault("BLINDPORT_TRANSPORT", "tcp"), "Blindport Port transport (tcp or udp)")
	claimDomain := flag.String("domain", os.Getenv("BLINDPORT_DOMAIN"), "Blindport Relay domain to claim (defaults to first allocated)")
	configPath := flag.String("config", os.Getenv("BLINDPORT_CONFIG"), "versioned JSON multi-mapping config file")
	dockerEnabled := flag.Bool("docker", envEnabled("BLINDPORT_DOCKER"), "continuously discover mappings and orders from running Docker container labels")
	dockerHost := flag.String("docker-host", envDefault("BLINDPORT_DOCKER_HOST", "unix:///var/run/docker.sock"), "absolute local unix:// Docker socket URL")
	dockerPollInterval := flag.Duration("docker-poll-interval", envDurationDefault("BLINDPORT_DOCKER_POLL_INTERVAL", 10*time.Second), "Docker discovery and backend reconciliation interval")
	insecureSkipTLS := flag.Bool("insecure-skip-tls", os.Getenv("BLINDPORT_INSECURE_SKIP_TLS") == "1", "skip mTLS on the control plane (insecure, dev only)")
	wireguardMode := flag.Bool("wireguard", envEnabled("BLINDPORT_WIREGUARD"), "configure the routed WireGuard Blindport IP plane instead of framed tunnels (Linux only)")
	wireguardInterface := flag.String("wireguard-interface", envDefault("BLINDPORT_WIREGUARD_INTERFACE", "bpwg0"), "routed WireGuard interface name")
	wireguardTable := flag.Int("wireguard-route-table", envIntDefault("BLINDPORT_WIREGUARD_ROUTE_TABLE", 51820), "policy routing table for routed replies")
	wireguardPriority := flag.Int("wireguard-rule-priority", envIntDefault("BLINDPORT_WIREGUARD_RULE_PRIORITY", 51820), "base priority for source policy rules")
	serverName := flag.String("server-name", os.Getenv("BLINDPORT_SERVER_NAME"), "TLS ServerName for every relay (defaults independently to each relay host)")
	socks5Address := flag.String("socks5", os.Getenv("BLINDPORT_SOCKS5"), "SOCKS5 proxy address for backend and relay connections (host:port)")
	stateDir := flag.String("state-dir", defaultCredentialStateDir(), "private directory for persistent client identity (or BLINDPORT_STATE_DIR)")
	acmeEmail := flag.String("acme-email", os.Getenv("BLINDPORT_ACME_EMAIL"), "optional ACME account contact email")
	acmeDirectory := flag.String("acme-directory", envDefault("BLINDPORT_ACME_DIRECTORY_URL", lego.LEDirectoryProduction), "ACME directory URL for automatic Relay TLS")
	flag.Parse()
	if *showVersion {
		fmt.Fprintf(os.Stdout, "blindportd %s\n", version)
		return
	}
	if *installUserServiceFlag {
		if err := installUserService(userServiceOptions{
			configPath: *configPath, tokenPath: *tokenFile, stateDir: *stateDir,
			wireguard: *wireguardMode, docker: *dockerEnabled,
			input: os.Stdin, output: os.Stdout,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "blindportd: install user service: %v\n", err)
			os.Exit(2)
		}
		return
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := validateOutboundMode(*wireguardMode, *socks5Address); err != nil {
		logger.Error("configure outbound mode", "err", err)
		os.Exit(2)
	}
	outbound, err := newOutboundTransport(*socks5Address)
	if err != nil {
		logger.Error("configure outbound transport", "err", err)
		os.Exit(2)
	}
	token, err := loadToken(*tokenFlag, *tokenFile)
	if err == nil && token == "" && *tokenFile == defaultTokenPath && defaultTokenPath != legacyTokenFile {
		token, err = loadToken("", legacyTokenFile)
	}
	if err == nil && token == "" {
		token, err = promptAndStoreToken(*tokenFile, os.Stdin, os.Stderr)
	}
	if err != nil {
		logger.Error("load token", "err", err)
		os.Exit(2)
	}
	if token == "" {
		logger.Error("no token: run blindportd interactively once or provide -token, BLINDPORT_TOKEN, or -token-file")
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	notifyAgentUpdate(ctx, logger, outbound.httpClient, *backendURL, token)

	if *wireguardMode {
		if *insecureSkipTLS {
			logger.Error("routed WireGuard requires the enrolled client identity; unset BLINDPORT_INSECURE_SKIP_TLS")
			os.Exit(2)
		}
		credentialStore, err := openCredentialManager(ctx, outbound.httpClient, *backendURL, token, *stateDir)
		if err != nil {
			logger.Error("initialize client identity", "err", err)
			os.Exit(1)
		}
		defer credentialStore.Close()
		go credentialStore.runRenewal(ctx, logger)
		if err := runWireGuard(ctx, logger, credentialStore, wireGuardAgentOptions{
			backendURL:   *backendURL,
			token:        token,
			httpClient:   outbound.httpClient,
			stateDir:     *stateDir,
			deviceName:   *wireguardInterface,
			routeTable:   *wireguardTable,
			rulePriority: *wireguardPriority,
		}); err != nil {
			logger.Error("routed WireGuard plane failed", "err", err)
			os.Exit(1)
		}
		return
	}

	multiMapping := *configPath != "" || *dockerEnabled
	var mappings []mapping
	if *configPath != "" {
		staticMappings, err := loadStaticConfig(*configPath)
		if err != nil {
			logger.Error("load config", "err", err)
			os.Exit(2)
		}
		mappings = append(mappings, staticMappings...)
	}
	if *dockerEnabled {
		if err := validateDockerPollInterval(*dockerPollInterval); err != nil {
			logger.Error("configure Docker discovery", "err", err)
			os.Exit(2)
		}
		logger.Warn("Docker daemon access is root-equivalent even when Blindport only lists containers", "host", *dockerHost)
		dockerClient, err := newDockerClient(*dockerHost)
		if err != nil {
			logger.Error("create Docker client", "err", err)
			os.Exit(2)
		}
		defer func() {
			if err := dockerClient.Close(); err != nil {
				logger.Warn("close Docker client", "err", err)
			}
		}()

		var material *tlsMaterial
		var credentialStore *credentialManager
		if !*insecureSkipTLS {
			credentialStore, err = openCredentialManager(ctx, outbound.httpClient, *backendURL, token, *stateDir)
			if err != nil {
				logger.Error("initialize client identity", "err", err)
				os.Exit(1)
			}
			defer credentialStore.Close()
			material = credentialStore.tlsMaterial()
			go credentialStore.runRenewal(ctx, logger)
		} else {
			logger.Warn("mTLS DISABLED (BLINDPORT_INSECURE_SKIP_TLS=1)")
		}

		acmeManagers, err := newLazyACMERegistry(ctx, *stateDir, *acmeDirectory, *acmeEmail, outbound.httpClient, logger)
		if err != nil {
			logger.Error("initialize automatic TLS state", "err", err)
			os.Exit(1)
		}
		defer acmeManagers.Close()
		supervisor := newWorkerSupervisor(ctx, func(workerCtx context.Context, plan workerPlan) {
			var tlsConfig *tls.Config
			if material != nil {
				var tlsErr error
				tlsConfig, tlsErr = material.configForEndpoint(plan.RelayAddr, *serverName)
				if tlsErr != nil {
					logger.Error("configure relay TLS", "relay", plan.RelayAddr, "err", tlsErr)
					return
				}
			}
			var automatic *acmeDomainManager
			if plan.TLSMode == tlsModeAutomatic && plan.Claim != nil {
				automatic = acmeManagers.manager(plan.Claim.Domain)
			}
			runWorker(workerCtx, logger, plan, token, outbound.relayDialer, tlsConfig, automatic)
		})
		agent := &dockerAgent{
			docker: dockerClient, static: mappings,
			orders: &orderAPIClient{client: outbound.httpClient, backend: *backendURL, token: token},
			fetchConfig: func(fetchCtx context.Context) ([]provisioning, error) {
				return fetchConfigWithClient(fetchCtx, outbound.httpClient, *backendURL, token)
			},
			supervisor: automaticPlanReconciler{registry: acmeManagers, workers: supervisor}, relayOverride: *relayOverride, pollInterval: *dockerPollInterval,
			logger: logger, now: time.Now, orderCache: make(map[string]*orderCacheEntry),
		}
		logger.Info("continuous Docker discovery started", "poll_interval", *dockerPollInterval, "static_mappings", len(mappings))
		agent.run(ctx)
		supervisor.Shutdown()
		return
	}
	if multiMapping {
		if len(mappings) == 0 {
			logger.Error("multi-mapping mode requires at least one static or Docker mapping")
			os.Exit(2)
		}
		if err := validateMappings(mappings); err != nil {
			logger.Error("invalid mappings", "err", err)
			os.Exit(2)
		}
	}

	cfg, err := fetchConfigWithClient(ctx, outbound.httpClient, *backendURL, token)
	if err != nil {
		logger.Error("fetch config", "err", err)
		os.Exit(1)
	}
	logger.Info("config fetched", "subscriptions", len(cfg))

	var plans []workerPlan
	if multiMapping {
		plans, err = buildMappingPlans(mappings, cfg, *relayOverride)
	} else {
		plans, err = buildLegacyPlans(cfg, legacySelection{
			kind: *claimKind, ip: *claimIP, port: *claimPort,
			transport: *claimTransport, domain: *claimDomain,
		}, *upstream, *httpChallengeUpstream, *relayOverride)
	}
	if err != nil {
		logger.Error("build tunnel plans", "err", err)
		os.Exit(2)
	}

	var material *tlsMaterial
	var credentialStore *credentialManager
	var certSerial string
	if !*insecureSkipTLS {
		credentialStore, err = openCredentialManager(ctx, outbound.httpClient, *backendURL, token, *stateDir)
		if err != nil {
			logger.Error("initialize client identity", "err", err)
			os.Exit(1)
		}
		defer credentialStore.Close()
		material = credentialStore.tlsMaterial()
		certSerial = credentialStore.serial()
		go credentialStore.runRenewal(ctx, logger)
	} else {
		logger.Warn("mTLS DISABLED (BLINDPORT_INSECURE_SKIP_TLS=1)")
	}

	tlsConfigs := make(map[string]*tls.Config, len(plans))
	for _, plan := range plans {
		var tlsConfig *tls.Config
		if material != nil {
			tlsConfig, err = material.configForEndpoint(plan.RelayAddr, *serverName)
			if err != nil {
				logger.Error("configure relay TLS", "relay", plan.RelayAddr, "err", err)
				os.Exit(2)
			}
			logger.Info("mTLS enabled", "relay", plan.RelayAddr, "server_name", tlsConfig.ServerName, "cert_serial", certSerial)
		}
		tlsConfigs[plan.RelayAddr] = tlsConfig
	}
	logger.Info("tunnel workers started", "workers", len(plans), "mappings", countMappings(plans))
	var acmeManagers *acmeRegistry
	if plansUseAutomaticTLS(plans) {
		acmeManagers, err = newACMERegistry(ctx, *stateDir, *acmeDirectory, *acmeEmail, outbound.httpClient, logger)
		if err != nil {
			logger.Error("initialize automatic TLS state", "err", err)
			os.Exit(1)
		}
		defer acmeManagers.Close()
		if err := acmeManagers.Reconcile(plans); err != nil {
			logger.Error("initialize automatic TLS managers", "err", err)
			os.Exit(1)
		}
	}
	runWorkerPlans(plans, func(plan workerPlan) {
		var automatic *acmeDomainManager
		if acmeManagers != nil && plan.Claim != nil {
			automatic = acmeManagers.manager(plan.Claim.Domain)
		}
		runWorker(ctx, logger, plan, token, outbound.relayDialer, tlsConfigs[plan.RelayAddr], automatic)
	})
}

func plansUseAutomaticTLS(plans []workerPlan) bool {
	for _, plan := range plans {
		if plan.TLSMode == tlsModeAutomatic {
			return true
		}
	}
	return false
}

func loadToken(flagValue, path string) (string, error) {
	if flagValue != "" {
		if err := validateToken(flagValue); err != nil {
			return "", fmt.Errorf("token argument: %w", err)
		}
		return flagValue, nil
	}
	if token := os.Getenv("BLINDPORT_TOKEN"); token != "" {
		if err := validateToken(token); err != nil {
			return "", fmt.Errorf("BLINDPORT_TOKEN: %w", err)
		}
		return token, nil
	}
	return loadTokenFile(path)
}

func loadTokenFile(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	file, err := openStaticConfig(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("open token file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("inspect token file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("token file must be regular")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("token file permissions %04o expose the bearer token", info.Mode().Perm())
	}
	if err := validateStaticConfigOwner(info); err != nil {
		return "", fmt.Errorf("token file: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil {
		return "", fmt.Errorf("read token file: %w", err)
	}
	if len(data) > 8192 {
		return "", errors.New("token file exceeds 8192 bytes")
	}
	token := strings.TrimSpace(string(data))
	if err := validateToken(token); err != nil {
		return "", fmt.Errorf("token file: %w", err)
	}
	return token, nil
}

type legacySelection struct {
	kind, ip, port, transport, domain string
}

func buildLegacyPlans(cfg []provisioning, selection legacySelection, upstream, httpChallengeUpstream, relayOverride string) ([]workerPlan, error) {
	requestedPort := uint16(0)
	if selection.port != "" {
		parsed, err := strconv.ParseUint(selection.port, 10, 16)
		if err != nil || parsed == 0 {
			return nil, fmt.Errorf("invalid Blindport Port number %q", selection.port)
		}
		requestedPort = uint16(parsed)
	}
	var chosen *provisioning
	if selection.kind == "" {
		switch len(cfg) {
		case 0:
			return nil, errors.New("no active framed subscriptions")
		case 1:
			chosen = &cfg[0]
		default:
			return nil, errors.New("multiple active framed subscriptions; use -config for explicit mappings or -kind to select one product")
		}
	} else {
		chosen = chooseProvisioning(cfg, selection.kind, selection.ip, requestedPort, selection.transport, selection.domain)
		if chosen == nil {
			return nil, fmt.Errorf("no matching active subscription for claim kind %q", selection.kind)
		}
	}
	if upstream == "" {
		upstream = "127.0.0.1:80"
		if chosen.Product == string(protocol.ClaimRelay) {
			upstream = "127.0.0.1:443"
		}
	}
	if err := validateHostPort(upstream); err != nil {
		return nil, fmt.Errorf("invalid upstream: %w", err)
	}
	return buildMappingPlans([]mapping{{SubscriptionID: chosen.SubscriptionID, Upstream: upstream, HTTPChallengeUpstream: httpChallengeUpstream, Source: "legacy flags"}}, cfg, relayOverride)
}

func countMappings(plans []workerPlan) int {
	ids := make(map[string]struct{}, len(plans))
	for _, plan := range plans {
		ids[plan.SubscriptionID] = struct{}{}
	}
	return len(ids)
}

func chooseProvisioning(cfg []provisioning, kind, ip string, port uint16, transport, domain string) *provisioning {
	for i := range cfg {
		row := &cfg[i]
		switch kind {
		case string(protocol.ClaimIP):
			if row.Product == kind && row.AssignedIP != "" && (ip == "" || ip == row.AssignedIP) {
				return row
			}
		case string(protocol.ClaimPort):
			if row.Product == kind && row.AssignedIP != "" && row.AssignedPort != 0 &&
				(ip == "" || ip == row.AssignedIP) && (port == 0 || port == row.AssignedPort) &&
				transport == row.Transport {
				return row
			}
		case string(protocol.ClaimRelay):
			if row.Product == kind && row.Domain != "" && (domain == "" || strings.EqualFold(domain, row.Domain)) {
				return row
			}
		}
	}
	return nil
}

func runOnce(ctx context.Context, log *slog.Logger, relayAddr, token string, claim *protocol.Claim, upstream, httpChallengeUpstream string, dialer contextDialer, tlsConfig *tls.Config) (time.Duration, error) {
	return runOnceManaged(ctx, log, relayAddr, token, claim, upstream, httpChallengeUpstream, dialer, tlsConfig, helloTimeout, nil)
}

func runOnceWithHelloTimeout(ctx context.Context, log *slog.Logger, relayAddr, token string, claim *protocol.Claim, upstream, httpChallengeUpstream string, dialer contextDialer, tlsConfig *tls.Config, timeout time.Duration) (time.Duration, error) {
	return runOnceManaged(ctx, log, relayAddr, token, claim, upstream, httpChallengeUpstream, dialer, tlsConfig, timeout, nil)
}

func runOnceManaged(ctx context.Context, log *slog.Logger, relayAddr, token string, claim *protocol.Claim, upstream, httpChallengeUpstream string, dialer contextDialer, tlsConfig *tls.Config, timeout time.Duration, automatic *acmeDomainManager) (time.Duration, error) {
	conn, err := dialRelay(ctx, dialer, relayAddr, tlsConfig)
	if err != nil {
		return 0, fmt.Errorf("dial relay: %w", err)
	}
	defer conn.Close()
	stopCancellation := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancellation()
	halfClose, err := exchangeHello(conn, token, claim, timeout)
	if err != nil {
		return 0, err
	}
	log.Info("tunnel established", "relay", relayAddr, "claim", claim, "upstream", upstream, "http_challenge_upstream", httpChallengeUpstream)

	expectedTransport := claimTransportForTunnel(claim)
	t := tunnel.New(conn, func(s *tunnel.Stream) {
		handleIncomingManaged(log, s, claim, upstream, httpChallengeUpstream, expectedTransport, automatic)
	})
	if halfClose {
		t.EnableTCPHalfClose()
	}
	if automatic != nil {
		automatic.edgeReady()
	}
	establishedAt := time.Now()
	err = t.Run()
	return time.Since(establishedAt), err
}

func dialRelay(ctx context.Context, dialer contextDialer, relayAddr string, tlsConfig *tls.Config) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, outboundDialTimeout)
	defer cancel()
	conn, err := dialer.DialContext(dialCtx, "tcp", relayAddr)
	if err != nil {
		return nil, err
	}
	if tlsConfig == nil {
		return conn, nil
	}
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func exchangeHello(conn net.Conn, token string, claim *protocol.Claim, timeout time.Duration) (bool, error) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return false, fmt.Errorf("set hello deadline: %w", err)
	}
	hello := &protocol.Frame{
		Type: protocol.TypeHello, Version: protocol.CurrentVersion, Token: token, Claim: claim,
		Capabilities: []protocol.Capability{protocol.CapabilityTCPHalfClose},
	}
	if err := protocol.WriteFrame(conn, hello); err != nil {
		return false, fmt.Errorf("send hello: %w", err)
	}
	reply, err := protocol.ReadFrame(conn)
	if err != nil {
		return false, fmt.Errorf("read hello reply: %w", err)
	}
	if reply.Type != protocol.TypeHelloOK {
		return false, fmt.Errorf("hello rejected: %s", reply.Msg)
	}
	if err := protocol.ValidateVersion(reply.Version, claim); err != nil {
		return false, fmt.Errorf("hello version: %w", err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return false, fmt.Errorf("clear hello deadline: %w", err)
	}
	return reply.HasCapability(protocol.CapabilityTCPHalfClose), nil
}

func claimTransportForTunnel(claim *protocol.Claim) protocol.Transport {
	if claim != nil && claim.Transport == protocol.TransportUDP {
		return protocol.TransportUDP
	}
	return protocol.TransportTCP
}

func handleIncoming(log *slog.Logger, s *tunnel.Stream, claim *protocol.Claim, upstream, httpChallengeUpstream string, expected protocol.Transport) {
	handleIncomingManaged(log, s, claim, upstream, httpChallengeUpstream, expected, nil)
}

func handleIncomingManaged(log *slog.Logger, s *tunnel.Stream, claim *protocol.Claim, upstream, httpChallengeUpstream string, expected protocol.Transport, automatic *acmeDomainManager) {
	if s.Protocol != expected {
		log.Warn("relay opened stream with unexpected transport", "expected", expected, "received", s.Protocol)
		_ = s.Close()
		return
	}
	if expected == protocol.TransportUDP {
		handleUDPAssociation(log, s, upstream)
		return
	}
	if automatic != nil {
		if claim == nil || claim.Kind != protocol.ClaimRelay || automatic.domain != claim.Domain {
			_ = s.Close()
			return
		}
		automatic.handleStream(log, s, upstream)
		return
	}
	selected, err := selectTCPUpstream(s.Destination, claim, upstream, httpChallengeUpstream)
	if err != nil {
		log.Warn("relay opened stream with unexpected destination", "destination", s.Destination, "err", err)
		_ = s.Close()
		return
	}
	handleTCPStream(log, s, selected)
}

func selectTCPUpstream(destination string, claim *protocol.Claim, upstream, httpChallengeUpstream string) (string, error) {
	if claim == nil || claim.Kind != protocol.ClaimRelay {
		return upstream, nil
	}
	prefix := "domain:" + claim.Domain + ":"
	switch destination {
	case prefix + "443":
		return upstream, nil
	case prefix + "80":
		if httpChallengeUpstream == "" {
			return "", errors.New("HTTP challenge upstream is disabled")
		}
		return httpChallengeUpstream, nil
	default:
		return "", errors.New("destination is outside the claimed Blindport Relay ports")
	}
}

func handleTCPStream(log *slog.Logger, s *tunnel.Stream, upstream string) {
	defer s.Close()
	up, err := net.DialTimeout("tcp", upstream, 5*time.Second)
	if err != nil {
		log.Warn("dial upstream", "err", err, "upstream", upstream)
		return
	}
	tcpproxy.Proxy(s, up)
}

func handleUDPAssociation(log *slog.Logger, s *tunnel.Stream, upstream string) {
	defer s.Close()
	up, err := net.DialTimeout("udp", upstream, 5*time.Second)
	if err != nil {
		log.Warn("dial UDP upstream", "err", err, "upstream", upstream)
		return
	}
	defer up.Close()
	done := make(chan struct{}, 2)
	go func() {
		buffer := make([]byte, protocol.MaxDatagramPayloadSize)
		for {
			n, err := s.ReadDatagram(buffer)
			if err != nil {
				break
			}
			if _, err := up.Write(buffer[:n]); err != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	go func() {
		buffer := make([]byte, protocol.MaxDatagramPayloadSize)
		for {
			n, err := up.Read(buffer)
			if err != nil {
				break
			}
			if _, err := s.WriteDatagram(buffer[:n]); err != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	<-done
	_ = up.Close()
	_ = s.Close()
	<-done
}

func fetchConfigWithClient(ctx context.Context, client *http.Client, backend, token string) ([]provisioning, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, backend+"/api/v1/client/config", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("config status %d", resp.StatusCode)
	}
	var cfg []provisioning
	if err := decodeBoundedJSON(resp.Body, maxProvisioningJSON, &cfg); err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(cfg))
	for _, row := range cfg {
		if err := validateSubscriptionID(row.SubscriptionID); err != nil {
			return nil, fmt.Errorf("invalid provisioning subscription_id %q: %w", row.SubscriptionID, err)
		}
		if _, exists := seen[row.SubscriptionID]; exists {
			return nil, fmt.Errorf("duplicate provisioning subscription_id %s", row.SubscriptionID)
		}
		seen[row.SubscriptionID] = struct{}{}
	}
	return cfg, nil
}

func notifyAgentUpdate(ctx context.Context, logger *slog.Logger, client *http.Client, backend, token string) {
	if version == "" || version == "dev" {
		return
	}
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	latest, err := fetchLatestAgentVersion(checkCtx, client, backend, token)
	if err != nil {
		logger.Debug("check for agent update", "err", err)
		return
	}
	if latest == "" || latest == "dev" || latest == version {
		return
	}
	downloadURL := strings.TrimRight(backend, "/") + "/downloads/install.sh"
	logger.Warn(
		"blindportd update available",
		"current_version", version,
		"latest_version", latest,
		"install_command", "curl -fsSL "+downloadURL+" | sh",
	)
}

func fetchLatestAgentVersion(ctx context.Context, client *http.Client, backend, token string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(backend, "/")+"/api/v1/client/version", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("version status %d", resp.StatusCode)
	}
	var result agentVersionResponse
	if err := decodeBoundedJSON(resp.Body, 1024, &result); err != nil {
		return "", fmt.Errorf("decode version: %w", err)
	}
	return result.Version, nil
}

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envEnabled(key string) bool {
	return os.Getenv(key) == "1"
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

func envDurationDefault(key string, def time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return def
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid %s duration %q: %v\n", key, value, err)
		os.Exit(2)
	}
	return parsed
}

// clientCert mirrors the JSON returned by GET /api/v1/client/cert.
type clientCert struct {
	CACertPEM     string `json:"ca_cert_pem"`
	ClientCertPEM string `json:"client_cert_pem"`
	ClientKeyPEM  string `json:"client_key_pem"`
	NotAfter      string `json:"not_after"`
	Serial        string `json:"serial"`
}

func fetchClientCertWithClient(ctx context.Context, client *http.Client, backend, token string) (*clientCert, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, backend+"/api/v1/client/cert", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cert status %d", resp.StatusCode)
	}
	var c clientCert
	if err := decodeBoundedJSON(resp.Body, maxCertificateResponse, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func decodeBoundedJSON(body io.Reader, limit int64, destination any) error {
	return decodeBoundedJSONReader(body, limit, destination, true)
}

func decodeBoundedJSONReader(body io.Reader, limit int64, destination any, strict bool) error {
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}
	if int64(len(data)) > limit {
		return fmt.Errorf("response body exceeds %d bytes", limit)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if strict {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode response JSON: %w", err)
	}
	if err := rejectTrailingJSON(decoder); err != nil {
		return fmt.Errorf("decode response JSON: %w", err)
	}
	return nil
}
