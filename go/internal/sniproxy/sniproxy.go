// Package sniproxy parses a TLS ClientHello to extract the SNI hostname
// without terminating TLS. It is used by the Blindport Relay shared-pool listener
// to dispatch inbound :443 connections to the correct user tunnel.
//
// The implementation peeks at the initial bytes on a net.Conn, decodes just
// enough of the ClientHello to read the SNI extension, and returns the
// hostname together with a wrapped net.Conn whose Read replays the peeked
// bytes followed by the rest of the stream.
package sniproxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// ErrNoSNI indicates the ClientHello did not include an SNI extension.
var ErrNoSNI = errors.New("no SNI in ClientHello")

const (
	tlsRecordHeaderLen    = 5
	maxTLSRecordLen       = 16 * 1024
	maxClientHelloLen     = 256 * 1024
	maxClientHelloRecords = 64
)

// PeekSNI reads (without consuming) a TLS ClientHello from conn and returns
// the server_name extension value. The returned net.Conn must be used in
// place of the original; it replays the peeked bytes transparently.
func PeekSNI(conn net.Conn, readDeadline time.Duration) (string, net.Conn, error) {
	if readDeadline > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(readDeadline))
	}
	handshake, replay, err := readClientHello(conn)
	if err != nil {
		return "", nil, err
	}
	name, err := parseSNI(handshake)
	if err != nil {
		return "", nil, err
	}
	if readDeadline > 0 {
		_ = conn.SetReadDeadline(time.Time{})
	}
	return name, &peekedConn{
		Conn: conn,
		r:    io.MultiReader(bytes.NewReader(replay), conn),
	}, nil
}

func readClientHello(conn io.Reader) ([]byte, []byte, error) {
	var handshake []byte
	var replay []byte
	expectedLen := 0

	for record := 0; record < maxClientHelloRecords; record++ {
		var header [tlsRecordHeaderLen]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return nil, nil, fmt.Errorf("read TLS record header: %w", err)
		}
		replay = append(replay, header[:]...)
		if header[0] != 0x16 { // handshake content type
			return nil, nil, fmt.Errorf("not a TLS handshake record (got 0x%x)", header[0])
		}

		recordLen := int(binary.BigEndian.Uint16(header[3:5]))
		if recordLen == 0 || recordLen > maxTLSRecordLen {
			return nil, nil, fmt.Errorf("bad TLS record length %d", recordLen)
		}
		payload := make([]byte, recordLen)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return nil, nil, fmt.Errorf("read TLS record body: %w", err)
		}
		replay = append(replay, payload...)

		if expectedLen == 0 {
			handshake = append(handshake, payload...)
			if len(handshake) < 4 {
				continue
			}
			if handshake[0] != 0x01 {
				return nil, nil, fmt.Errorf("not a ClientHello (type=0x%x)", handshake[0])
			}
			expectedLen = 4 + (int(handshake[1]) << 16) + (int(handshake[2]) << 8) + int(handshake[3])
			if expectedLen > maxClientHelloLen {
				return nil, nil, fmt.Errorf("ClientHello length %d exceeds limit", expectedLen)
			}
		} else {
			remaining := expectedLen - len(handshake)
			if remaining > len(payload) {
				remaining = len(payload)
			}
			handshake = append(handshake, payload[:remaining]...)
		}

		if len(handshake) >= expectedLen {
			return handshake[:expectedLen], replay, nil
		}
	}

	return nil, nil, fmt.Errorf("ClientHello exceeds %d TLS records", maxClientHelloRecords)
}

func parseSNI(body []byte) (string, error) {
	// body = handshake message: type(1) | length(3) | client_hello
	if len(body) < 4 {
		return "", errors.New("body too short")
	}
	if body[0] != 0x01 { // ClientHello
		return "", fmt.Errorf("not a ClientHello (type=0x%x)", body[0])
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if hsLen+4 != len(body) {
		return "", errors.New("bad handshake length")
	}
	p := body[4 : 4+hsLen]
	// skip: client_version(2) random(32) session_id(1+n) cipher_suites(2+n) comp_methods(1+n)
	if len(p) < 2+32+1 {
		return "", errors.New("client_hello too short")
	}
	p = p[2+32:]
	sidLen := int(p[0])
	if 1+sidLen > len(p) {
		return "", errors.New("bad session_id len")
	}
	p = p[1+sidLen:]
	if len(p) < 2 {
		return "", errors.New("missing cipher_suites len")
	}
	csLen := int(binary.BigEndian.Uint16(p[:2]))
	if 2+csLen > len(p) {
		return "", errors.New("bad cipher_suites len")
	}
	p = p[2+csLen:]
	if len(p) < 1 {
		return "", errors.New("missing comp_methods len")
	}
	cmLen := int(p[0])
	if 1+cmLen > len(p) {
		return "", errors.New("bad comp_methods len")
	}
	p = p[1+cmLen:]
	if len(p) < 2 {
		return "", ErrNoSNI
	}
	extLen := int(binary.BigEndian.Uint16(p[:2]))
	p = p[2:]
	if extLen != len(p) {
		return "", errors.New("bad extensions len")
	}
	ext := p[:extLen]
	serverName := ""
	for len(ext) >= 4 {
		extType := binary.BigEndian.Uint16(ext[:2])
		l := int(binary.BigEndian.Uint16(ext[2:4]))
		if 4+l > len(ext) {
			return "", errors.New("bad extension item")
		}
		data := ext[4 : 4+l]
		ext = ext[4+l:]
		if extType == 0x0000 { // server_name
			if len(data) < 2 {
				return "", errors.New("bad SNI list len")
			}
			listLen := int(binary.BigEndian.Uint16(data[:2]))
			if listLen == 0 || listLen+2 != len(data) {
				return "", errors.New("bad SNI list len")
			}
			list := data[2 : 2+listLen]
			for len(list) > 0 {
				if len(list) < 3 {
					return "", errors.New("bad SNI name")
				}
				nameType := list[0]
				nlen := int(binary.BigEndian.Uint16(list[1:3]))
				if 3+nlen > len(list) {
					return "", errors.New("bad SNI name")
				}
				if nameType == 0 { // host_name
					name := list[3 : 3+nlen]
					if len(name) == 0 {
						return "", errors.New("empty SNI host_name")
					}
					if bytes.IndexByte(name, 0) >= 0 {
						return "", errors.New("SNI host_name contains NUL")
					}
					if serverName != "" {
						return "", errors.New("duplicate SNI host_name")
					}
					serverName = strings.ToLower(string(name))
				}
				list = list[3+nlen:]
			}
		}
	}
	if len(ext) != 0 {
		return "", errors.New("bad extension header")
	}
	if serverName != "" {
		return serverName, nil
	}
	return "", ErrNoSNI
}

type peekedConn struct {
	net.Conn
	r io.Reader
}

func (p *peekedConn) Read(b []byte) (int, error) { return p.r.Read(b) }

func (p *peekedConn) CloseWrite() error {
	if conn, ok := p.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return p.Conn.Close()
}
