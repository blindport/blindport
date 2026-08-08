// Package protocol defines the wire protocol between the Blindport client
// daemon (blindportd) and the relay node (blindport-relay).
//
// The protocol is intentionally simple: each frame is a 4-byte big-endian
// length prefix followed by a JSON payload of the corresponding length.
// Frames are exchanged over a single TCP connection (optionally wrapped in
// TLS in production).
//
// The first frame from the client must be a HelloFrame; the first from the
// server must be a HelloOk or HelloErr. After the handshake, multiplexed
// streams transport application traffic.
package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
)

// FrameType enumerates the message kinds.
type FrameType string

const (
	TypeHello        FrameType = "hello"
	TypeHelloOK      FrameType = "hello_ok"
	TypeHelloErr     FrameType = "hello_err"
	TypeOpen         FrameType = "open"
	TypeData         FrameType = "data"
	TypeDatagram     FrameType = "datagram"
	TypeWindowUpdate FrameType = "window_update"
	TypeCloseWrite   FrameType = "close_write"
	TypeClose        FrameType = "close"
	TypePing         FrameType = "ping"
	TypePong         FrameType = "pong"
)

// Capability identifies an independently negotiated protocol extension.
type Capability string

const (
	// CapabilityTCPHalfClose permits CLOSE_WRITE frames on TCP streams.
	CapabilityTCPHalfClose Capability = "tcp_half_close"
	// CapabilityStreamFlowControl permits per-stream WINDOW_UPDATE credit.
	CapabilityStreamFlowControl Capability = "stream_flow_control"
	// CapabilityOfflineEntitlementV1 permits a Hello frame to carry a v1 offline entitlement.
	CapabilityOfflineEntitlementV1 Capability = "offline_entitlement_v1"
)

// ClaimKind identifies which product the client is claiming on this tunnel.
type ClaimKind string

const (
	ClaimIP    ClaimKind = "ip"
	ClaimPort  ClaimKind = "port"
	ClaimRelay ClaimKind = "relay"
)

// Transport identifies the L4 transport bound by a claim.
type Transport string

const (
	TransportTCP Transport = "tcp"
	TransportUDP Transport = "udp"
)

// Claim describes which resource the client wants to bind to this tunnel.
type Claim struct {
	Kind      ClaimKind `json:"kind"`
	IP        string    `json:"ip,omitempty"`
	Domain    string    `json:"domain,omitempty"`
	Port      uint16    `json:"port,omitempty"`
	Transport Transport `json:"transport,omitempty"`
}

var hostnameLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidateClaim rejects unknown products and ambiguous field combinations.
func ValidateClaim(c *Claim) error {
	if c == nil {
		return errors.New("claim is required")
	}
	validIP := net.ParseIP(c.IP) != nil
	transportOK := c.Transport == "" || c.Transport == TransportTCP
	switch c.Kind {
	case ClaimIP:
		if !validIP || c.Domain != "" || c.Port != 0 || !transportOK {
			return errors.New("ip claim requires only an IP and optional tcp transport")
		}
	case ClaimPort:
		if !validIP || c.Domain != "" || c.Port == 0 || (c.Transport != TransportTCP && c.Transport != TransportUDP) {
			return errors.New("port claim requires IP, nonzero port, and tcp or udp transport")
		}
	case ClaimRelay:
		if !validHostname(c.Domain) || c.IP != "" || c.Port != 0 || !transportOK {
			return errors.New("relay claim requires only a valid hostname and optional tcp transport")
		}
	default:
		return fmt.Errorf("unknown claim kind %q", c.Kind)
	}
	return nil
}

func validHostname(value string) bool {
	if value == "" || len(value) > 253 || net.ParseIP(value) != nil || value != strings.ToLower(value) {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if !hostnameLabel.MatchString(label) {
			return false
		}
	}
	return true
}

// Frame is the union envelope for all messages.
type Frame struct {
	Type         FrameType    `json:"type"`
	Version      uint16       `json:"version,omitempty"`
	Token        string       `json:"token,omitempty"`
	Entitlement  string       `json:"entitlement,omitempty"`
	Claim        *Claim       `json:"claim,omitempty"`
	Msg          string       `json:"msg,omitempty"`
	Stream       uint32       `json:"stream,omitempty"`
	Proto        string       `json:"proto,omitempty"`
	Src          string       `json:"src,omitempty"`
	Dst          string       `json:"dst,omitempty"`
	Data         []byte       `json:"data,omitempty"`
	Credit       uint32       `json:"credit,omitempty"`
	Capabilities []Capability `json:"capabilities,omitempty"`
}

// HasCapability reports whether a handshake frame advertises capability.
func (f *Frame) HasCapability(capability Capability) bool {
	for _, offered := range f.Capabilities {
		if offered == capability {
			return true
		}
	}
	return false
}

const (
	// CurrentVersion adds UDP Blindport Port datagrams while retaining legacy TCP framing.
	CurrentVersion uint16 = 1
	// MaxFrameSize caps a single encoded frame at 1 MiB to bound memory.
	MaxFrameSize = 1 << 20
	// MaxHelloFrameSize bounds the unauthenticated control-plane handshake.
	MaxHelloFrameSize = 8 << 10
	// MaxDataPayloadSize bounds application data carried by one DATA frame.
	MaxDataPayloadSize = 16 << 10
	// MaxDatagramPayloadSize is the largest valid IPv4 UDP payload.
	MaxDatagramPayloadSize = 65507
	// MaxWindowUpdate is the largest credit increment accepted in one frame.
	MaxWindowUpdate = 4 << 20
)

// ValidateVersion permits unversioned legacy TCP sessions and requires the
// current protocol version for UDP datagrams.
func ValidateVersion(version uint16, claim *Claim) error {
	if version > CurrentVersion {
		return fmt.Errorf("unsupported protocol version %d", version)
	}
	if claim != nil && claim.Transport == TransportUDP && version != CurrentVersion {
		return fmt.Errorf("UDP requires protocol version %d", CurrentVersion)
	}
	return nil
}

// WriteFrame writes one frame to w.
func WriteFrame(w io.Writer, f *Frame) error {
	if f.Type == TypeData && len(f.Data) > MaxDataPayloadSize {
		return fmt.Errorf("data payload too large: %d > %d", len(f.Data), MaxDataPayloadSize)
	}
	if f.Type == TypeDatagram && len(f.Data) > MaxDatagramPayloadSize {
		return fmt.Errorf("datagram payload too large: %d > %d", len(f.Data), MaxDatagramPayloadSize)
	}
	b, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("marshal frame: %w", err)
	}
	if len(b) > MaxFrameSize {
		return fmt.Errorf("frame too large: %d > %d", len(b), MaxFrameSize)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write hdr: %w", err)
	}
	if _, err := w.Write(b); err != nil {
		return fmt.Errorf("write body: %w", err)
	}
	return nil
}

// ReadFrame reads one frame from r.
func ReadFrame(r io.Reader) (*Frame, error) {
	return ReadFrameWithLimit(r, MaxFrameSize)
}

// ReadFrameWithLimit reads one frame from r with a caller-selected size cap.
// The limit must not exceed the protocol-wide maximum.
func ReadFrameWithLimit(r io.Reader, limit uint32) (*Frame, error) {
	if limit == 0 || limit > MaxFrameSize {
		return nil, fmt.Errorf("invalid frame limit: %d", limit)
	}
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return nil, errors.New("zero-length frame")
	}
	if n > limit {
		return nil, fmt.Errorf("frame too large: %d > %d", n, limit)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	var f Frame
	if err := json.Unmarshal(buf, &f); err != nil {
		return nil, fmt.Errorf("decode frame: %w", err)
	}
	if f.Type == TypeData && len(f.Data) > MaxDataPayloadSize {
		return nil, fmt.Errorf("data payload too large: %d > %d", len(f.Data), MaxDataPayloadSize)
	}
	if f.Type == TypeDatagram && len(f.Data) > MaxDatagramPayloadSize {
		return nil, fmt.Errorf("datagram payload too large: %d > %d", len(f.Data), MaxDatagramPayloadSize)
	}
	return &f, nil
}
