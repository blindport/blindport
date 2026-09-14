package wgnet

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

const (
	maxGatewayPortRanges = 64
	maxGatewayPorts      = 1024
)

// PortRange is an inclusive TCP or UDP port interval.
type PortRange struct {
	Start uint16
	End   uint16
}

// ParsePortRanges accepts one canonical comma-separated list of ports and
// inclusive ranges, for example "80,443,8000-8010". Empty means deny all.
func ParsePortRanges(value string) ([]PortRange, error) {
	if value == "" {
		return nil, nil
	}
	if strings.TrimSpace(value) != value {
		return nil, errors.New("port ranges must not contain leading or trailing whitespace")
	}
	parts := strings.Split(value, ",")
	if len(parts) > maxGatewayPortRanges {
		return nil, fmt.Errorf("port ranges exceed %d entries", maxGatewayPortRanges)
	}
	ranges := make([]PortRange, 0, len(parts))
	previousEnd := 0
	total := 0
	for _, part := range parts {
		if part == "" || strings.Count(part, "-") > 1 {
			return nil, fmt.Errorf("invalid port range %q", part)
		}
		values := strings.Split(part, "-")
		start, err := parseCanonicalPort(values[0])
		if err != nil {
			return nil, err
		}
		end := start
		if len(values) == 2 {
			end, err = parseCanonicalPort(values[1])
			if err != nil {
				return nil, err
			}
			if start >= end {
				return nil, fmt.Errorf("port range %q must have an ascending range", part)
			}
		}
		if int(start) <= previousEnd {
			return nil, fmt.Errorf("port range %q overlaps or is out of order", part)
		}
		width := int(end) - int(start) + 1
		if total+width > maxGatewayPorts {
			return nil, fmt.Errorf("port ranges exceed %d ports", maxGatewayPorts)
		}
		ranges = append(ranges, PortRange{Start: start, End: end})
		previousEnd = int(end)
		total += width
	}
	return ranges, nil
}

func parseCanonicalPort(value string) (uint16, error) {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return 0, fmt.Errorf("port %q must be canonical", value)
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, fmt.Errorf("port %q must be decimal", value)
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 16)
	if err != nil || parsed == 0 {
		return 0, fmt.Errorf("port %q must be within 1-65535", value)
	}
	return uint16(parsed), nil
}

// GatewayFirewallConfig is the fail-closed local policy for gateway mode.
type GatewayFirewallConfig struct {
	InterfaceName  string
	RelayInterface string
	RelayEndpoint  netip.Addr
	RelayPort      uint16
	TCPPorts       []PortRange
	UDPPorts       []PortRange
	AllowICMP      bool
}

// GatewayNFTFirewall atomically owns only inet blindport-agent.
type GatewayNFTFirewall struct {
	config GatewayFirewallConfig
	runner CommandRunner
}

// NewGatewayNFTFirewall creates a gateway kill switch using the production nft executable.
func NewGatewayNFTFirewall(config GatewayFirewallConfig) (*GatewayNFTFirewall, error) {
	return newGatewayNFTFirewall(config, execCommandRunner{})
}

func newGatewayNFTFirewall(config GatewayFirewallConfig, runner CommandRunner) (*GatewayNFTFirewall, error) {
	if err := validateGatewayFirewallConfig(config); err != nil {
		return nil, err
	}
	if runner == nil {
		return nil, errors.New("nft command runner is required")
	}
	return &GatewayNFTFirewall{config: config, runner: runner}, nil
}

// Apply installs the kill switch as one nft transaction.
func (f *GatewayNFTFirewall) Apply() error {
	rules, err := RenderGatewayNFTPolicy(f.config)
	if err != nil {
		return err
	}
	output, err := f.runner.Run(NFTExecutable, []string{"-f", "-"}, rules)
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if detail != "" {
			return fmt.Errorf("apply gateway nft policy: %w: %s", err, detail)
		}
		return fmt.Errorf("apply gateway nft policy: %w", err)
	}
	return nil
}

// RenderGatewayNFTPolicy renders the dedicated local gateway kill switch.
func RenderGatewayNFTPolicy(config GatewayFirewallConfig) ([]byte, error) {
	if err := validateGatewayFirewallConfig(config); err != nil {
		return nil, err
	}
	var rules strings.Builder
	rules.WriteString("destroy table inet blindport-agent\n")
	rules.WriteString("table inet blindport-agent {\n")
	writeNFTPortSet(&rules, "gateway_tcp_ports", config.TCPPorts)
	writeNFTPortSet(&rules, "gateway_udp_ports", config.UDPPorts)
	device := strconv.Quote(config.InterfaceName)
	relayDevice := strconv.Quote(config.RelayInterface)
	rules.WriteString("\tchain input {\n")
	rules.WriteString("\t\ttype filter hook input priority filter; policy accept;\n")
	fmt.Fprintf(&rules, "\t\tiifname %s ct state established,related counter accept comment %s\n", device, strconv.Quote("blindport_gateway_return_traffic"))
	fmt.Fprintf(&rules, "\t\tiifname %s tcp dport @gateway_tcp_ports counter accept comment %s\n", device, strconv.Quote("blindport_gateway_tcp_input"))
	fmt.Fprintf(&rules, "\t\tiifname %s udp dport @gateway_udp_ports counter accept comment %s\n", device, strconv.Quote("blindport_gateway_udp_input"))
	if config.AllowICMP {
		fmt.Fprintf(&rules, "\t\tiifname %s icmp type echo-request counter accept comment %s\n", device, strconv.Quote("blindport_gateway_icmp_input"))
	}
	fmt.Fprintf(&rules, "\t\tiifname %s counter drop comment %s\n", device, strconv.Quote("blindport_gateway_input_default_deny"))
	rules.WriteString("\t}\n")
	rules.WriteString("\tchain output {\n")
	rules.WriteString("\t\ttype filter hook output priority filter; policy drop;\n")
	rules.WriteString("\t\toifname \"lo\" counter accept comment \"blindport_gateway_loopback\"\n")
	rules.WriteString("\t\tmeta nfproto ipv6 counter drop comment \"blindport_gateway_ipv6_leak\"\n")
	fmt.Fprintf(&rules, "\t\toifname %s counter accept comment %s\n", device, strconv.Quote("blindport_gateway_tunnel"))
	// Docker's embedded resolver is reached at this loopback address. Both DNS
	// transports are explicitly limited to avoid opening the Docker interface.
	rules.WriteString("\t\tip daddr 127.0.0.11 udp dport 53 counter accept comment \"blindport_gateway_docker_dns\"\n")
	rules.WriteString("\t\tip daddr 127.0.0.11 tcp dport 53 counter accept comment \"blindport_gateway_docker_dns\"\n")
	fmt.Fprintf(&rules, "\t\tip daddr %s oifname %s udp dport %d counter accept comment %s\n", config.RelayEndpoint, relayDevice, config.RelayPort, strconv.Quote("blindport_gateway_relay"))
	rules.WriteString("\t\tmeta nfproto ipv4 counter drop comment \"blindport_gateway_ipv4_leak\"\n")
	rules.WriteString("\t}\n")
	rules.WriteString("}\n")
	return []byte(rules.String()), nil
}

func validateGatewayFirewallConfig(config GatewayFirewallConfig) error {
	if err := ValidateInterfaceName(config.InterfaceName); err != nil {
		return err
	}
	if err := ValidateInterfaceName(config.RelayInterface); err != nil {
		return fmt.Errorf("relay interface: %w", err)
	}
	if !config.RelayEndpoint.Is4() {
		return errors.New("relay endpoint must be IPv4")
	}
	if config.RelayPort == 0 {
		return errors.New("relay endpoint port must be within 1-65535")
	}
	for _, ranges := range [][]PortRange{config.TCPPorts, config.UDPPorts} {
		if err := validatePortRanges(ranges); err != nil {
			return err
		}
	}
	return nil
}

func validatePortRanges(ranges []PortRange) error {
	if len(ranges) > maxGatewayPortRanges {
		return fmt.Errorf("port ranges exceed %d entries", maxGatewayPortRanges)
	}
	previous := 0
	total := 0
	for _, portRange := range ranges {
		if portRange.Start == 0 || portRange.End < portRange.Start || int(portRange.Start) <= previous {
			return errors.New("port ranges must be ordered, non-overlapping, and within 1-65535")
		}
		total += int(portRange.End) - int(portRange.Start) + 1
		if total > maxGatewayPorts {
			return fmt.Errorf("port ranges exceed %d ports", maxGatewayPorts)
		}
		previous = int(portRange.End)
	}
	return nil
}

func writeNFTPortSet(rules *strings.Builder, name string, ranges []PortRange) {
	values := make([]string, 0, len(ranges))
	for _, portRange := range ranges {
		if portRange.Start == portRange.End {
			values = append(values, strconv.Itoa(int(portRange.Start)))
		} else {
			values = append(values, fmt.Sprintf("%d-%d", portRange.Start, portRange.End))
		}
	}
	sort.Strings(values)
	fmt.Fprintf(rules, "\tset %s {\n\t\ttype inet_service\n\t\tflags interval\n", name)
	if len(values) != 0 {
		fmt.Fprintf(rules, "\t\telements = { %s }\n", strings.Join(values, ", "))
	}
	rules.WriteString("\t}\n")
}
