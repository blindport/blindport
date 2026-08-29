// Package proxyproto encodes and parses PROXY protocol v2 trusted ingress metadata.
package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

var signature = [12]byte{'\r', '\n', '\r', '\n', 0, '\r', '\n', 'Q', 'U', 'I', 'T', '\n'}

const (
	v2FixedHeaderLength = 16
	maxV2PayloadLength  = 4096
)

// WrapListener requires each accepted connection to start with a PROXY protocol
// v2 TCP header. headerTimeout bounds reading that header and must be positive.
// The header payload, including TCP address data and trailing TLVs, is limited to
// 4 KiB. The returned listener closes connections whose header is invalid.
func WrapListener(listener net.Listener, headerTimeout time.Duration) (net.Listener, error) {
	if listener == nil {
		return nil, errors.New("listener is required")
	}
	if headerTimeout <= 0 {
		return nil, errors.New("PROXY v2 header timeout must be positive")
	}
	return &v2Listener{Listener: listener, headerTimeout: headerTimeout}, nil
}

type v2Listener struct {
	net.Listener
	headerTimeout time.Duration
}

func (l *v2Listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if err := conn.SetReadDeadline(time.Now().Add(l.headerTimeout)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("set PROXY v2 header deadline: %w", err)
	}

	remoteAddr, localAddr, err := readV2Header(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("clear PROXY v2 header deadline: %w", err)
	}
	return &v2Conn{Conn: conn, remoteAddr: remoteAddr, localAddr: localAddr}, nil
}

type v2Conn struct {
	net.Conn
	remoteAddr *net.TCPAddr
	localAddr  *net.TCPAddr
}

func (c *v2Conn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *v2Conn) LocalAddr() net.Addr { return c.localAddr }

func readV2Header(conn net.Conn) (*net.TCPAddr, *net.TCPAddr, error) {
	var fixed [v2FixedHeaderLength]byte
	if _, err := io.ReadFull(conn, fixed[:]); err != nil {
		return nil, nil, fmt.Errorf("read PROXY v2 header: %w", err)
	}
	if !bytes.Equal(fixed[:len(signature)], signature[:]) {
		return nil, nil, errors.New("invalid PROXY v2 signature")
	}
	if fixed[12]>>4 != 0x2 {
		return nil, nil, errors.New("invalid PROXY v2 version")
	}
	if fixed[12]&0x0f != 0x1 {
		return nil, nil, errors.New("unsupported PROXY v2 command")
	}

	addressLength, err := v2AddressLength(fixed[13])
	if err != nil {
		return nil, nil, err
	}
	payloadLength := int(binary.BigEndian.Uint16(fixed[14:16]))
	if payloadLength > maxV2PayloadLength {
		return nil, nil, errors.New("PROXY v2 payload exceeds limit")
	}
	if payloadLength < addressLength {
		return nil, nil, errors.New("invalid PROXY v2 payload length")
	}

	payload := make([]byte, payloadLength)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, nil, fmt.Errorf("read PROXY v2 payload: %w", err)
	}
	if err := validateV2TLVs(payload[addressLength:]); err != nil {
		return nil, nil, err
	}

	source, destination, sourcePort, destinationPort := v2Addresses(fixed[13], payload)
	if source.Unmap().IsUnspecified() {
		return nil, nil, errors.New("PROXY v2 source address is unspecified")
	}
	if sourcePort == 0 {
		return nil, nil, errors.New("PROXY v2 source port is zero")
	}
	return tcpAddr(source, sourcePort), tcpAddr(destination, destinationPort), nil
}

func v2AddressLength(familyTransport byte) (int, error) {
	switch familyTransport {
	case 0x11:
		return 12, nil
	case 0x21:
		return 36, nil
	default:
		return 0, errors.New("unsupported PROXY v2 family or transport")
	}
}

func validateV2TLVs(tlvs []byte) error {
	for len(tlvs) != 0 {
		if len(tlvs) < 3 {
			return errors.New("truncated PROXY v2 TLV")
		}
		length := int(binary.BigEndian.Uint16(tlvs[1:3]))
		tlvs = tlvs[3:]
		if length > len(tlvs) {
			return errors.New("truncated PROXY v2 TLV value")
		}
		tlvs = tlvs[length:]
	}
	return nil
}

func v2Addresses(familyTransport byte, payload []byte) (netip.Addr, netip.Addr, uint16, uint16) {
	if familyTransport == 0x11 {
		source, _ := netip.AddrFromSlice(payload[:4])
		destination, _ := netip.AddrFromSlice(payload[4:8])
		return source, destination, binary.BigEndian.Uint16(payload[8:10]), binary.BigEndian.Uint16(payload[10:12])
	}
	source, _ := netip.AddrFromSlice(payload[:16])
	destination, _ := netip.AddrFromSlice(payload[16:32])
	return source, destination, binary.BigEndian.Uint16(payload[32:34]), binary.BigEndian.Uint16(payload[34:36])
}

func tcpAddr(address netip.Addr, port uint16) *net.TCPAddr {
	return &net.TCPAddr{IP: append(net.IP(nil), address.AsSlice()...), Port: int(port)}
}

// V2 returns a PROXY protocol v2 TCP header for the supplied addresses.
func V2(source, destination string) ([]byte, error) {
	sourceAddr, sourcePort, err := parseAddress(source)
	if err != nil {
		return nil, errors.New("invalid source address")
	}
	destinationAddr, destinationPort, err := parseAddress(destination)
	if err != nil {
		return nil, errors.New("invalid destination address")
	}
	if sourceAddr.IsUnspecified() {
		return nil, errors.New("source address is unspecified")
	}
	if sourceAddr.Is4() {
		if !destinationAddr.Is4() || destinationAddr.IsUnspecified() {
			destinationAddr = netip.IPv4Unspecified()
		}
		result := make([]byte, 28)
		copy(result, signature[:])
		result[12], result[13] = 0x21, 0x11
		binary.BigEndian.PutUint16(result[14:16], 12)
		copy(result[16:20], sourceAddr.AsSlice())
		copy(result[20:24], destinationAddr.AsSlice())
		binary.BigEndian.PutUint16(result[24:26], sourcePort)
		binary.BigEndian.PutUint16(result[26:28], destinationPort)
		return result, nil
	}
	if !destinationAddr.Is6() || destinationAddr.IsUnspecified() {
		destinationAddr = netip.IPv6Unspecified()
	}
	result := make([]byte, 52)
	copy(result, signature[:])
	result[12], result[13] = 0x21, 0x21
	binary.BigEndian.PutUint16(result[14:16], 36)
	copy(result[16:32], sourceAddr.AsSlice())
	copy(result[32:48], destinationAddr.AsSlice())
	binary.BigEndian.PutUint16(result[48:50], sourcePort)
	binary.BigEndian.PutUint16(result[50:52], destinationPort)
	return result, nil
}

// WriteV2 writes the complete PROXY protocol v2 header before application data.
func WriteV2(w io.Writer, source, destination string) error {
	header, err := V2(source, destination)
	if err != nil {
		return err
	}
	for len(header) != 0 {
		n, err := w.Write(header)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		header = header[n:]
	}
	return nil
}

func parseAddress(value string) (netip.Addr, uint16, error) {
	host, rawPort, err := net.SplitHostPort(value)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	if host, _, found := strings.Cut(host, "%"); found {
		// A zone identifies a local interface, not wire address bytes.
		value = host
	} else {
		value = host
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	addr = addr.Unmap()
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || port == 0 || strconv.FormatUint(port, 10) != rawPort {
		return netip.Addr{}, 0, errors.New("invalid port")
	}
	return addr, uint16(port), nil
}
