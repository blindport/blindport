//go:build linux

package wgnet

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// RouteProtocol tags every route owned by Blindport so reconciliation never
// touches operator- or kernel-managed routes.
const RouteProtocol = 157

// EnsureDevice creates or adopts one WireGuard link and brings it up.
func EnsureDevice(name string, mtu int) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if !errors.As(err, &notFound) {
			return fmt.Errorf("inspect link %s: %w", name, err)
		}
		wireguardLink := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: name, MTU: mtu}}
		if err := netlink.LinkAdd(wireguardLink); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create WireGuard link %s: %w", name, err)
		}
		if link, err = netlink.LinkByName(name); err != nil {
			return fmt.Errorf("inspect created link %s: %w", name, err)
		}
	}
	if link.Type() != "wireguard" {
		return fmt.Errorf("link %s exists but is %s, not wireguard", name, link.Type())
	}
	if link.Attrs().MTU != mtu {
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			return fmt.Errorf("set %s MTU: %w", name, err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring up %s: %w", name, err)
	}
	return nil
}

// ConfigureRelayDevice installs the relay private key and listen port.
func ConfigureRelayDevice(name string, privateKey wgtypes.Key, listenPort int) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("open WireGuard control: %w", err)
	}
	defer client.Close()
	if err := client.ConfigureDevice(name, wgtypes.Config{
		PrivateKey: &privateKey,
		ListenPort: &listenPort,
	}); err != nil {
		return fmt.Errorf("configure relay device %s: %w", name, err)
	}
	return nil
}

// LinuxRelayDataplane applies desired peers and routes with wgctrl and netlink.
type LinuxRelayDataplane struct {
	deviceName string
	linkIndex  int
	firewall   *NFTFirewall
}

// NewLinuxRelayDataplane binds one existing WireGuard device.
func NewLinuxRelayDataplane(deviceName string) (*LinuxRelayDataplane, error) {
	return NewLinuxRelayDataplaneWithPolicy(deviceName, false)
}

// NewLinuxRelayDataplaneWithPolicy binds the device with an explicit private
// destination policy. Private destinations are permitted only for isolated tests.
func NewLinuxRelayDataplaneWithPolicy(deviceName string, allowPrivate bool) (*LinuxRelayDataplane, error) {
	link, err := netlink.LinkByName(deviceName)
	if err != nil {
		return nil, fmt.Errorf("inspect WireGuard device %s: %w", deviceName, err)
	}
	firewall, err := newNFTFirewall(deviceName, allowPrivate, execCommandRunner{})
	if err != nil {
		return nil, err
	}
	dataplane := &LinuxRelayDataplane{deviceName: deviceName, linkIndex: link.Attrs().Index, firewall: firewall}
	if err := failCloseRelayStartup(dataplane); err != nil {
		return nil, err
	}
	return dataplane, nil
}

type relayStartupDataplane interface {
	ApplyRoutedPolicy(activePrefixes, smtpAllowedPrefixes []string) error
	blackholeActiveOwnedRoutes() error
	ReplacePeers(peers []Peer) error
}

func failCloseRelayStartup(dataplane relayStartupDataplane) error {
	var failures []error
	if err := dataplane.ReplacePeers(nil); err != nil {
		failures = append(failures, fmt.Errorf("remove existing WireGuard peers: %w", err))
	}
	if err := dataplane.ApplyRoutedPolicy(nil, nil); err != nil {
		failures = append(failures, fmt.Errorf("install initial fail-closed routed policy: %w", err))
	}
	if err := dataplane.blackholeActiveOwnedRoutes(); err != nil {
		failures = append(failures, fmt.Errorf("fail closed existing routed prefixes: %w", err))
	}
	return errors.Join(failures...)
}

// ApplyRoutedPolicy atomically replaces the nftables policy for routed peers.
func (d *LinuxRelayDataplane) ApplyRoutedPolicy(activePrefixes, smtpAllowedPrefixes []string) error {
	return d.firewall.Apply(activePrefixes, smtpAllowedPrefixes)
}

// ReplacePeers reconciles exactly the desired peer set without recreating
// unchanged peers. Updating a peer in place preserves its learned roaming
// endpoint and handshake state.
func (d *LinuxRelayDataplane) ReplacePeers(peers []Peer) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("open WireGuard control: %w", err)
	}
	defer client.Close()
	device, err := client.Device(d.deviceName)
	if err != nil {
		return fmt.Errorf("inspect WireGuard device %s: %w", d.deviceName, err)
	}
	configs, err := relayPeerConfigs(device.Peers, peers)
	if err != nil {
		return err
	}
	if err := client.ConfigureDevice(d.deviceName, wgtypes.Config{Peers: configs}); err != nil {
		return fmt.Errorf("reconcile peers on %s: %w", d.deviceName, err)
	}
	return nil
}

func relayPeerConfigs(current []wgtypes.Peer, desired []Peer) ([]wgtypes.PeerConfig, error) {
	desiredKeys := make(map[wgtypes.Key]struct{}, len(desired))
	configs := make([]wgtypes.PeerConfig, 0, len(current)+len(desired))
	for _, peer := range desired {
		key, err := wgtypes.ParseKey(peer.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("parse peer key: %w", err)
		}
		desiredKeys[key] = struct{}{}
	}
	for _, peer := range current {
		if _, keep := desiredKeys[peer.PublicKey]; !keep {
			configs = append(configs, wgtypes.PeerConfig{
				PublicKey: peer.PublicKey,
				Remove:    true,
			})
		}
	}
	for _, peer := range desired {
		key, err := wgtypes.ParseKey(peer.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("parse peer key: %w", err)
		}
		allowed := make([]net.IPNet, 0, len(peer.AllowedPrefixes))
		for _, prefix := range peer.AllowedPrefixes {
			network, err := prefixToIPNet(prefix)
			if err != nil {
				return nil, err
			}
			allowed = append(allowed, *network)
		}
		configs = append(configs, wgtypes.PeerConfig{
			PublicKey:         key,
			ReplaceAllowedIPs: true,
			AllowedIPs:        allowed,
		})
	}
	return configs, nil
}

// ActivateRoute routes one leased prefix into the WireGuard device.
func (d *LinuxRelayDataplane) ActivateRoute(prefix string) error {
	destination, err := prefixToIPNet(prefix)
	if err != nil {
		return err
	}
	return netlink.RouteReplace(&netlink.Route{
		Dst:       destination,
		LinkIndex: d.linkIndex,
		Scope:     netlink.SCOPE_LINK,
		Protocol:  RouteProtocol,
	})
}

// BlackholeRoute drops one managed prefix so inactive inventory never loops
// back through the provider default route.
func (d *LinuxRelayDataplane) BlackholeRoute(prefix string) error {
	destination, err := prefixToIPNet(prefix)
	if err != nil {
		return err
	}
	return netlink.RouteReplace(&netlink.Route{
		Dst:      destination,
		Type:     unix.RTN_BLACKHOLE,
		Protocol: RouteProtocol,
	})
}

func (d *LinuxRelayDataplane) blackholeActiveOwnedRoutes() error {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
		LinkIndex: d.linkIndex,
		Protocol:  RouteProtocol,
	}, netlink.RT_FILTER_OIF|netlink.RT_FILTER_PROTOCOL)
	if err != nil {
		return fmt.Errorf("list Blindport routes: %w", err)
	}
	for _, route := range routes {
		if route.Dst == nil {
			return errors.New("Blindport route has no destination")
		}
		if err := d.BlackholeRoute(route.Dst.String()); err != nil {
			return fmt.Errorf("blackhole existing route %s: %w", route.Dst, err)
		}
	}
	return nil
}

// AgentConfig is the complete local state for one routed agent.
type AgentConfig struct {
	DeviceName          string
	PrivateKey          wgtypes.Key
	RelayPublicKey      string
	Endpoint            string
	MTU                 int
	Prefixes            []string
	PersistentKeepalive time.Duration
	RouteTable          int
	RulePriority        int
}

// ConfigureAgent creates the agent device, relay peer, leased addresses, and
// source-policy routing without changing the host default route.
func ConfigureAgent(config AgentConfig) error {
	if err := EnsureDevice(config.DeviceName, config.MTU); err != nil {
		return err
	}
	relayKey, err := wgtypes.ParseKey(config.RelayPublicKey)
	if err != nil {
		return fmt.Errorf("parse relay public key: %w", err)
	}
	endpoint, err := net.ResolveUDPAddr("udp", config.Endpoint)
	if err != nil {
		return fmt.Errorf("resolve relay endpoint %q: %w", config.Endpoint, err)
	}
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("open WireGuard control: %w", err)
	}
	defer client.Close()
	keepalive := config.PersistentKeepalive
	_, allTraffic, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil { // pragma: unreachable constant parse
		return err
	}
	if err := client.ConfigureDevice(config.DeviceName, wgtypes.Config{
		PrivateKey:   &config.PrivateKey,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{{
			PublicKey:                   relayKey,
			Endpoint:                    endpoint,
			PersistentKeepaliveInterval: &keepalive,
			ReplaceAllowedIPs:           true,
			AllowedIPs:                  []net.IPNet{*allTraffic},
		}},
	}); err != nil {
		return fmt.Errorf("configure agent device %s: %w", config.DeviceName, err)
	}

	link, err := netlink.LinkByName(config.DeviceName)
	if err != nil {
		return fmt.Errorf("inspect agent device %s: %w", config.DeviceName, err)
	}
	desiredAddresses := make(map[string]*net.IPNet, len(config.Prefixes))
	for _, prefix := range config.Prefixes {
		address, err := prefixToIPNet(prefix)
		if err != nil {
			return err
		}
		desiredAddresses[address.String()] = address
	}
	currentAddresses, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("list addresses on %s: %w", config.DeviceName, err)
	}
	previousSources := make(map[string]struct{}, len(currentAddresses))
	for _, address := range currentAddresses {
		if address.IPNet != nil {
			previousSources[address.IPNet.String()] = struct{}{}
		}
	}
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("list IPv4 policy rules: %w", err)
	}
	for _, rule := range rules {
		if !isOwnedAgentRule(rule, previousSources, config.RouteTable) {
			continue
		}
		candidate := rule
		if err := netlink.RuleDel(&candidate); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale source rule %s: %w", rule.String(), err)
		}
	}
	for _, address := range currentAddresses {
		if address.IPNet == nil {
			continue
		}
		if _, desired := desiredAddresses[address.IPNet.String()]; desired {
			continue
		}
		candidate := address
		if err := netlink.AddrDel(link, &candidate); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale address %s from %s: %w", address.IPNet, config.DeviceName, err)
		}
	}
	for _, prefix := range config.Prefixes {
		address := desiredAddresses[prefix]
		if address == nil {
			return fmt.Errorf("resolve desired address %s", prefix)
		}
		if err := netlink.AddrReplace(link, &netlink.Addr{IPNet: address}); err != nil {
			return fmt.Errorf("assign %s to %s: %w", prefix, config.DeviceName, err)
		}
	}
	if err := netlink.RouteReplace(&netlink.Route{
		Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
		Table:     config.RouteTable,
		Protocol:  RouteProtocol,
	}); err != nil {
		return fmt.Errorf("install policy default route: %w", err)
	}
	for offset, prefix := range config.Prefixes {
		source, err := prefixToIPNet(prefix)
		if err != nil {
			return err
		}
		rule := netlink.NewRule()
		rule.Family = netlink.FAMILY_V4
		rule.Src = source
		rule.Table = config.RouteTable
		rule.Priority = config.RulePriority + offset
		rule.Protocol = RouteProtocol
		if err := netlink.RuleAdd(rule); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("install source rule for %s: %w", prefix, err)
		}
	}
	return nil
}

func isOwnedAgentRule(rule netlink.Rule, previousSources map[string]struct{}, routeTable int) bool {
	if rule.Protocol == RouteProtocol {
		return true
	}
	if rule.Table != routeTable || rule.Src == nil || rule.Dst != nil || rule.Mark != 0 ||
		rule.IifName != "" || rule.OifName != "" {
		return false
	}
	_, previous := previousSources[rule.Src.String()]
	return previous
}

func prefixToIPNet(prefix string) (*net.IPNet, error) {
	parsed, err := ValidatePrefix(prefix)
	if err != nil {
		return nil, err
	}
	address := parsed.Addr().As4()
	return &net.IPNet{IP: net.IP(address[:]), Mask: net.CIDRMask(32, 32)}, nil
}
