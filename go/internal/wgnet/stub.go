//go:build !linux

package wgnet

import (
	"errors"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ErrUnsupportedPlatform reports that routed WireGuard needs Linux.
var ErrUnsupportedPlatform = errors.New("routed WireGuard requires Linux")

// RouteProtocol matches the Linux implementation for documentation purposes.
const RouteProtocol = 157

// EnsureDevice is unavailable outside Linux.
func EnsureDevice(string, int) error { return ErrUnsupportedPlatform }

// ConfigureRelayDevice is unavailable outside Linux.
func ConfigureRelayDevice(string, wgtypes.Key, int) error { return ErrUnsupportedPlatform }

// LinuxRelayDataplane is unavailable outside Linux.
type LinuxRelayDataplane struct{}

// NewLinuxRelayDataplane is unavailable outside Linux.
func NewLinuxRelayDataplane(string) (*LinuxRelayDataplane, error) {
	return nil, ErrUnsupportedPlatform
}

// NewLinuxRelayDataplaneWithPolicy is unavailable outside Linux.
func NewLinuxRelayDataplaneWithPolicy(string, bool) (*LinuxRelayDataplane, error) {
	return nil, ErrUnsupportedPlatform
}

// ReplacePeers is unavailable outside Linux.
func (*LinuxRelayDataplane) ReplacePeers([]Peer) error { return ErrUnsupportedPlatform }

// ApplyRoutedPolicy is unavailable outside Linux.
func (*LinuxRelayDataplane) ApplyRoutedPolicy([]string, []string) error {
	return ErrUnsupportedPlatform
}

// ActivateRoute is unavailable outside Linux.
func (*LinuxRelayDataplane) ActivateRoute(string) error { return ErrUnsupportedPlatform }

// BlackholeRoute is unavailable outside Linux.
func (*LinuxRelayDataplane) BlackholeRoute(string) error { return ErrUnsupportedPlatform }

// AgentConfig mirrors the Linux agent configuration.
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

// ConfigureAgent is unavailable outside Linux.
func ConfigureAgent(AgentConfig) error { return ErrUnsupportedPlatform }
