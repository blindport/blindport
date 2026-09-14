package proxyproto

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestV2EncodesTCPAddresses(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		destination string
		family      byte
		length      int
		wantSource  []byte
		wantDest    []byte
	}{
		{"IPv4", "192.0.2.1:1234", "198.51.100.2:443", 0x11, 28, []byte{192, 0, 2, 1}, []byte{198, 51, 100, 2}},
		{"IPv6 zone", "[2001:db8::1%eth0]:1234", "[2001:db8::2]:443", 0x21, 52, []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}},
		{"IPv4 mapped", "[::ffff:192.0.2.1]:1234", "[::ffff:198.51.100.2]:443", 0x11, 28, []byte{192, 0, 2, 1}, []byte{198, 51, 100, 2}},
		{"family mismatch", "192.0.2.1:1234", "[2001:db8::2]:443", 0x11, 28, []byte{192, 0, 2, 1}, []byte{0, 0, 0, 0}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			header, err := V2(test.source, test.destination)
			if err != nil {
				t.Fatal(err)
			}
			if len(header) != test.length || header[12] != 0x21 || header[13] != test.family {
				t.Fatalf("header = %x", header)
			}
			if !bytes.Equal(header[16:16+len(test.wantSource)], test.wantSource) || !bytes.Equal(header[16+len(test.wantSource):16+len(test.wantSource)+len(test.wantDest)], test.wantDest) {
				t.Fatalf("address bytes = %x", header)
			}
			if got := binary.BigEndian.Uint16(header[len(header)-4 : len(header)-2]); got != 1234 {
				t.Fatalf("source port = %d", got)
			}
			if got := binary.BigEndian.Uint16(header[len(header)-2:]); got != 443 {
				t.Fatalf("destination port = %d", got)
			}
		})
	}
}

func TestWriteV2CompletesShortWrites(t *testing.T) {
	writer := &shortWriter{maximum: 3}
	if err := WriteV2(writer, "192.0.2.1:1234", "198.51.100.2:443"); err != nil {
		t.Fatal(err)
	}
	if len(writer.Bytes()) != 28 || writer.Bytes()[12] != 0x21 || writer.Bytes()[13] != 0x11 {
		t.Fatalf("written header = %x", writer.Bytes())
	}
}

type shortWriter struct {
	bytes.Buffer
	maximum int
}

func (w *shortWriter) Write(payload []byte) (int, error) {
	if len(payload) > w.maximum {
		payload = payload[:w.maximum]
	}
	return w.Buffer.Write(payload)
}

func TestV2RejectsMissingOrMalformedMetadata(t *testing.T) {
	for _, test := range [][2]string{{"", "192.0.2.2:443"}, {"192.0.2.1:123", ""}, {"not-an-address", "192.0.2.2:443"}, {"0.0.0.0:123", "192.0.2.2:443"}} {
		if _, err := V2(test[0], test[1]); err == nil {
			t.Fatalf("V2(%q, %q) succeeded", test[0], test[1])
		}
	}
}
