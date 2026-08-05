package wgnet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// NFTExecutable is fixed to the path installed in the production relay image.
	NFTExecutable = "/usr/sbin/nft"
	nftTimeout    = 10 * time.Second
)

var nonGlobalIPv4Prefixes = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.88.99.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
}

// CommandRunner executes one command with supplied standard input.
type CommandRunner interface {
	Run(name string, args []string, stdin []byte) ([]byte, error)
}

type execCommandRunner struct{}

func (execCommandRunner) Run(name string, args []string, stdin []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), nftTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = bytes.NewReader(stdin)
	output, err := command.CombinedOutput()
	if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return output, fmt.Errorf("command timed out: %w", ctx.Err())
	}
	return output, err
}

// NFTFirewall atomically owns only the inet blindport nftables table.
type NFTFirewall struct {
	interfaceName string
	allowPrivate  bool
	runner        CommandRunner
}

// NewNFTFirewall creates a firewall using the production nft executable.
func NewNFTFirewall(interfaceName string) (*NFTFirewall, error) {
	return newNFTFirewall(interfaceName, false, execCommandRunner{})
}

func newNFTFirewall(interfaceName string, allowPrivate bool, runner CommandRunner) (*NFTFirewall, error) {
	if err := ValidateInterfaceName(interfaceName); err != nil {
		return nil, err
	}
	if runner == nil {
		return nil, errors.New("nft command runner is required")
	}
	return &NFTFirewall{interfaceName: interfaceName, allowPrivate: allowPrivate, runner: runner}, nil
}

// Apply replaces the complete Blindport policy in one nft transaction.
func (f *NFTFirewall) Apply(activePrefixes, smtpAllowedPrefixes []string) error {
	ruleset, err := renderNFTPolicy(
		f.interfaceName,
		activePrefixes,
		smtpAllowedPrefixes,
		f.allowPrivate,
	)
	if err != nil {
		return err
	}
	output, err := f.runner.Run(NFTExecutable, []string{"-f", "-"}, ruleset)
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if detail != "" {
			return fmt.Errorf("apply nft policy: %w: %s", err, detail)
		}
		return fmt.Errorf("apply nft policy: %w", err)
	}
	return nil
}

// ValidateInterfaceName accepts conservative Linux interface identifiers.
func ValidateInterfaceName(name string) error {
	if name == "" || len(name) > 15 {
		return fmt.Errorf("WireGuard interface name %q must contain 1-15 characters", name)
	}
	for _, character := range name {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '_' || character == '.' || character == '-' {
			continue
		}
		return fmt.Errorf("WireGuard interface name %q contains an unsafe character", name)
	}
	return nil
}

// RenderNFTPolicy renders a complete, deterministic inet blindport table.
func RenderNFTPolicy(interfaceName string, activePrefixes, smtpAllowedPrefixes []string) ([]byte, error) {
	return renderNFTPolicy(interfaceName, activePrefixes, smtpAllowedPrefixes, false)
}

func renderNFTPolicy(
	interfaceName string,
	activePrefixes, smtpAllowedPrefixes []string,
	allowPrivate bool,
) ([]byte, error) {
	if err := ValidateInterfaceName(interfaceName); err != nil {
		return nil, err
	}
	active, err := nftAddresses(activePrefixes)
	if err != nil {
		return nil, fmt.Errorf("active prefixes: %w", err)
	}
	smtpAllowed, err := nftAddresses(smtpAllowedPrefixes)
	if err != nil {
		return nil, fmt.Errorf("SMTP allowed prefixes: %w", err)
	}

	var rules strings.Builder
	rules.WriteString("destroy table inet blindport\n")
	rules.WriteString("table inet blindport {\n")
	writeNFTSet(&rules, "active_ipv4", active, false)
	writeNFTSet(&rules, "smtp_allowed_ipv4", smtpAllowed, false)
	if !allowPrivate {
		writeNFTSet(&rules, "non_global_ipv4", nonGlobalIPv4Prefixes, true)
	}
	quotedInterface := strconv.Quote(interfaceName)
	rules.WriteString("\tchain input {\n")
	rules.WriteString("\t\ttype filter hook input priority filter; policy accept;\n")
	fmt.Fprintf(&rules, "\t\tiifname %s ct state established,related counter accept comment %s\n", quotedInterface, strconv.Quote("blindport_relay_return_traffic"))
	fmt.Fprintf(&rules, "\t\tiifname %s counter drop comment %s\n", quotedInterface, strconv.Quote("blindport_relay_input"))
	rules.WriteString("\t}\n")
	rules.WriteString("\tchain smtp_policy {\n")
	rules.WriteString("\t\tip saddr @smtp_allowed_ipv4 counter return comment \"blindport_smtp_allowed\"\n")
	rules.WriteString("\t\tcounter drop comment \"blindport_smtp_denied\"\n")
	rules.WriteString("\t}\n")
	rules.WriteString("\tchain forward {\n")
	rules.WriteString("\t\ttype filter hook forward priority filter; policy accept;\n")
	fmt.Fprintf(&rules, "\t\tiifname %s meta nfproto ipv6 counter reject with icmpv6 type admin-prohibited comment %s\n", quotedInterface, strconv.Quote("blindport_invalid_source"))
	fmt.Fprintf(&rules, "\t\tiifname %s ip saddr != @active_ipv4 counter reject with icmp type admin-prohibited comment %s\n", quotedInterface, strconv.Quote("blindport_invalid_source"))
	fmt.Fprintf(&rules, "\t\tiifname %s ct state established,related counter accept comment %s\n", quotedInterface, strconv.Quote("blindport_return_traffic"))
	rules.WriteString("\t}\n")
	rules.WriteString("\tchain postrouting {\n")
	rules.WriteString("\t\ttype filter hook postrouting priority filter; policy accept;\n")
	rules.WriteString("\t\tct direction original ip saddr @active_ipv4 tcp dport 25 jump smtp_policy\n")
	if !allowPrivate {
		fmt.Fprintf(&rules, "\t\tct direction original ip saddr @active_ipv4 ip daddr @non_global_ipv4 counter drop comment %s\n", strconv.Quote("blindport_non_global_destination"))
	}
	rules.WriteString("\t}\n")
	rules.WriteString("}\n")
	return []byte(rules.String()), nil
}

func nftAddresses(prefixes []string) ([]string, error) {
	addresses := make([]string, 0, len(prefixes))
	seen := make(map[string]struct{}, len(prefixes))
	for _, value := range prefixes {
		prefix, err := ValidatePrefix(value)
		if err != nil {
			return nil, err
		}
		address := prefix.Addr().String()
		if _, exists := seen[address]; exists {
			return nil, fmt.Errorf("duplicate prefix %s", value)
		}
		seen[address] = struct{}{}
		addresses = append(addresses, address)
	}
	sort.Strings(addresses)
	return addresses, nil
}

func writeNFTSet(rules *strings.Builder, name string, elements []string, interval bool) {
	fmt.Fprintf(rules, "\tset %s {\n\t\ttype ipv4_addr\n", name)
	if interval {
		rules.WriteString("\t\tflags interval\n")
	}
	if len(elements) != 0 {
		fmt.Fprintf(rules, "\t\telements = { %s }\n", strings.Join(elements, ", "))
	}
	rules.WriteString("\t}\n")
}
