//go:build linux

package wgnet

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// GatewayConfig is the complete local state for an all-traffic WireGuard gateway.
type GatewayConfig struct {
	AgentConfig
	TCPPorts  []PortRange
	UDPPorts  []PortRange
	AllowICMP bool
}

type gatewayRelayPath struct {
	interfaceName string
	linkIndex     int
}

type gatewayPolicyApplier interface {
	ApplyFirewall() error
	AddEndpointException() error
	AddAllTrafficRule() error
}

func applyGatewayPolicy(applier gatewayPolicyApplier) error {
	if err := applier.ApplyFirewall(); err != nil {
		return fmt.Errorf("install gateway kill switch: %w", err)
	}
	if err := applier.AddEndpointException(); err != nil {
		return fmt.Errorf("install relay endpoint exception: %w", err)
	}
	if err := applier.AddAllTrafficRule(); err != nil {
		return fmt.Errorf("install all-traffic WireGuard rule: %w", err)
	}
	return nil
}

// ConfigureGatewayAgent configures a single-address all-traffic gateway. The
// nft kill switch is installed before either policy rule can select the tunnel.
func ConfigureGatewayAgent(config GatewayConfig) error {
	if len(config.Prefixes) != 1 {
		return errors.New("WireGuard gateway requires exactly one assigned IPv4 /32")
	}
	address, err := prefixToIPNet(config.Prefixes[0])
	if err != nil {
		return err
	}
	if config.RulePriority >= 32765 {
		return errors.New("WireGuard gateway rules would overlap the Linux main route-table priority")
	}
	endpoint, err := net.ResolveUDPAddr("udp4", config.Endpoint)
	if err != nil || endpoint.IP == nil || endpoint.IP.To4() == nil || endpoint.Port == 0 {
		if err != nil {
			return fmt.Errorf("resolve relay endpoint %q: %w", config.Endpoint, err)
		}
		return fmt.Errorf("resolve relay endpoint %q: endpoint must be IPv4 with a port", config.Endpoint)
	}
	path, err := captureGatewayRelayPath(endpoint.IP)
	if err != nil {
		return err
	}
	if path.interfaceName == config.DeviceName {
		return errors.New("relay endpoint already routes through the WireGuard interface")
	}
	if err := EnsureDevice(config.DeviceName, config.MTU); err != nil {
		return err
	}
	relayKey, err := wgtypes.ParseKey(config.RelayPublicKey)
	if err != nil {
		return fmt.Errorf("parse relay public key: %w", err)
	}
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("open WireGuard control: %w", err)
	}
	defer client.Close()
	keepalive := config.PersistentKeepalive
	_, allTraffic, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		return err
	}
	if err := client.ConfigureDevice(config.DeviceName, wgtypes.Config{
		PrivateKey: &config.PrivateKey, ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{{
			PublicKey: relayKey, Endpoint: endpoint, PersistentKeepaliveInterval: &keepalive,
			ReplaceAllowedIPs: true, AllowedIPs: []net.IPNet{*allTraffic},
		}},
	}); err != nil {
		return fmt.Errorf("configure agent device %s: %w", config.DeviceName, err)
	}
	link, err := netlink.LinkByName(config.DeviceName)
	if err != nil {
		return fmt.Errorf("inspect agent device %s: %w", config.DeviceName, err)
	}
	if err := reconcileGatewayAddressAndRules(link, address, config.RouteTable); err != nil {
		return err
	}
	if err := netlink.RouteReplace(&netlink.Route{
		Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}, LinkIndex: link.Attrs().Index,
		Scope: netlink.SCOPE_LINK, Table: config.RouteTable, Protocol: RouteProtocol,
	}); err != nil {
		return fmt.Errorf("install gateway default route: %w", err)
	}
	relayAddress, ok := netip.AddrFromSlice(endpoint.IP.To4())
	if !ok {
		return errors.New("convert relay endpoint IPv4")
	}
	firewall, err := NewGatewayNFTFirewall(GatewayFirewallConfig{
		InterfaceName: config.DeviceName, RelayInterface: path.interfaceName, RelayEndpoint: relayAddress,
		RelayPort: uint16(endpoint.Port), TCPPorts: config.TCPPorts, UDPPorts: config.UDPPorts, AllowICMP: config.AllowICMP,
	})
	if err != nil {
		return err
	}
	return applyGatewayPolicy(&linuxGatewayPolicy{
		firewall: firewall, endpoint: endpoint.IP.To4(), routeTable: config.RouteTable,
		rulePriority: config.RulePriority,
	})
}

func captureGatewayRelayPath(endpoint net.IP) (gatewayRelayPath, error) {
	routes, err := netlink.RouteGet(endpoint)
	if err != nil || len(routes) != 1 {
		if err != nil {
			return gatewayRelayPath{}, fmt.Errorf("capture main route to relay endpoint %s: %w", endpoint, err)
		}
		return gatewayRelayPath{}, fmt.Errorf("capture main route to relay endpoint %s: expected one route, got %d", endpoint, len(routes))
	}
	route := routes[0]
	if route.LinkIndex == 0 || (route.Table != 0 && route.Table != unix.RT_TABLE_MAIN) {
		return gatewayRelayPath{}, fmt.Errorf("relay endpoint %s has no usable main-route path", endpoint)
	}
	link, err := netlink.LinkByIndex(route.LinkIndex)
	if err != nil {
		return gatewayRelayPath{}, fmt.Errorf("inspect main-route interface for relay endpoint %s: %w", endpoint, err)
	}
	if link.Attrs().Name == "" {
		return gatewayRelayPath{}, errors.New("main-route interface has no name")
	}
	if err := ValidateInterfaceName(link.Attrs().Name); err != nil {
		return gatewayRelayPath{}, fmt.Errorf("main-route interface: %w", err)
	}
	return gatewayRelayPath{interfaceName: link.Attrs().Name, linkIndex: route.LinkIndex}, nil
}

func reconcileGatewayAddressAndRules(link netlink.Link, address *net.IPNet, routeTable int) error {
	current, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("list addresses on %s: %w", link.Attrs().Name, err)
	}
	previous := make(map[string]struct{}, len(current))
	for _, candidate := range current {
		if candidate.IPNet != nil {
			previous[candidate.IPNet.String()] = struct{}{}
		}
	}
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("list IPv4 policy rules: %w", err)
	}
	for _, rule := range rules {
		if !isOwnedAgentRule(rule, previous, routeTable) {
			continue
		}
		candidate := rule
		if err := netlink.RuleDel(&candidate); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale WireGuard rule %s: %w", rule.String(), err)
		}
	}
	for _, candidate := range current {
		if candidate.IPNet == nil || candidate.IPNet.String() == address.String() {
			continue
		}
		stale := candidate
		if err := netlink.AddrDel(link, &stale); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale address %s from %s: %w", candidate.IPNet, link.Attrs().Name, err)
		}
	}
	if err := netlink.AddrReplace(link, &netlink.Addr{IPNet: address}); err != nil {
		return fmt.Errorf("assign %s to %s: %w", address, link.Attrs().Name, err)
	}
	return nil
}

type linuxGatewayPolicy struct {
	firewall     *GatewayNFTFirewall
	endpoint     net.IP
	routeTable   int
	rulePriority int
}

func (p *linuxGatewayPolicy) ApplyFirewall() error { return p.firewall.Apply() }

func (p *linuxGatewayPolicy) AddEndpointException() error {
	rule := netlink.NewRule()
	rule.Family = netlink.FAMILY_V4
	rule.Dst = &net.IPNet{IP: p.endpoint, Mask: net.CIDRMask(32, 32)}
	rule.Table = unix.RT_TABLE_MAIN
	rule.Priority = p.rulePriority
	rule.Protocol = RouteProtocol
	if err := netlink.RuleAdd(rule); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return nil
}

func (p *linuxGatewayPolicy) AddAllTrafficRule() error {
	rule := netlink.NewRule()
	rule.Family = netlink.FAMILY_V4
	rule.Table = p.routeTable
	rule.Priority = p.rulePriority + 1
	rule.Protocol = RouteProtocol
	if err := netlink.RuleAdd(rule); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return nil
}
