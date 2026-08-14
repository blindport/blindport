// Package proxyproto encodes PROXY protocol v2 headers for trusted ingress metadata.
package proxyproto

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

var signature = [12]byte{'\r', '\n', '\r', '\n', 0, '\r', '\n', 'Q', 'U', 'I', 'T', '\n'}

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
