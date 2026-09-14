package sniproxy

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeConn implements net.Conn over a bytes.Reader for the read side.
type fakeConn struct {
	r io.Reader
	net.Conn
}

func (f *fakeConn) Read(b []byte) (int, error)         { return f.r.Read(b) }
func (f *fakeConn) Write(b []byte) (int, error)        { return len(b), nil }
func (f *fakeConn) Close() error                       { return nil }
func (f *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(t time.Time) error { return nil }
func (f *fakeConn) SetDeadline(t time.Time) error      { return nil }

func makeClientHello(host string, paddingLen int) []byte {
	name := []byte(host)
	nameEntry := make([]byte, 3+len(name))
	binary.BigEndian.PutUint16(nameEntry[1:3], uint16(len(name)))
	copy(nameEntry[3:], name)

	sniData := make([]byte, 2+len(nameEntry))
	binary.BigEndian.PutUint16(sniData[:2], uint16(len(nameEntry)))
	copy(sniData[2:], nameEntry)

	extensions := make([]byte, 4+len(sniData))
	binary.BigEndian.PutUint16(extensions[2:4], uint16(len(sniData)))
	copy(extensions[4:], sniData)
	if paddingLen > 0 {
		padding := make([]byte, 4+paddingLen)
		binary.BigEndian.PutUint16(padding[:2], 0x0015)
		binary.BigEndian.PutUint16(padding[2:4], uint16(paddingLen))
		extensions = append(extensions, padding...)
	}

	body := make([]byte, 0, 43+len(extensions))
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)             // session ID length
	body = append(body, 0, 2, 0x13, 1) // cipher suites
	body = append(body, 1, 0)          // compression methods
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)

	handshake := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(handshake, body...)
}

func makeTLSRecord(contentType byte, payload []byte) []byte {
	record := []byte{contentType, 0x03, 0x01, byte(len(payload) >> 8), byte(len(payload))}
	return append(record, payload...)
}

func makeTLSRecords(handshake []byte, splitPoints ...int) []byte {
	var records []byte
	start := 0
	for _, end := range append(splitPoints, len(handshake)) {
		records = append(records, makeTLSRecord(0x16, handshake[start:end])...)
		start = end
	}
	return records
}

func TestPeekSNIWithRealClientHello(t *testing.T) {
	// Generate a real ClientHello by starting an in-memory TLS handshake.
	cliConn, srvConn := net.Pipe()
	defer cliConn.Close()
	defer srvConn.Close()

	go func() {
		// run a TLS client (it will fail because no real server, but it
		// will write a ClientHello before any server response is required).
		_ = tls.Client(cliConn, &tls.Config{ServerName: "alice.example.com", InsecureSkipVerify: true}).Handshake()
	}()

	var header [5]byte
	if _, err := io.ReadFull(srvConn, header[:]); err != nil {
		t.Fatalf("read client hello header: %v", err)
	}
	hello := append([]byte(nil), header[:]...)
	payload := make([]byte, int(binary.BigEndian.Uint16(header[3:5])))
	if _, err := io.ReadFull(srvConn, payload); err != nil {
		t.Fatalf("read client hello body: %v", err)
	}
	hello = append(hello, payload...)

	fc := &fakeConn{r: bytes.NewReader(hello)}
	name, _, err := PeekSNI(fc, 0)
	if err != nil {
		t.Fatalf("PeekSNI: %v", err)
	}
	if name != "alice.example.com" {
		t.Fatalf("want alice.example.com, got %q", name)
	}
}

func TestPeekSNISplitAcrossHandshakeRecords(t *testing.T) {
	handshake := makeClientHello("Split.Example.COM", 0)
	tests := []struct {
		name        string
		splitPoints []int
	}{
		{name: "handshake header", splitPoints: []int{1, 3}},
		{name: "client hello fields", splitPoints: []int{4, 17, 41}},
		{name: "SNI extension", splitPoints: []int{47, len(handshake) - 2}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stream := makeTLSRecords(handshake, tt.splitPoints...)
			name, replay, err := PeekSNI(&fakeConn{r: bytes.NewReader(stream)}, 0)
			if err != nil {
				t.Fatalf("PeekSNI: %v", err)
			}
			if name != "split.example.com" {
				t.Fatalf("want split.example.com, got %q", name)
			}
			got, err := io.ReadAll(replay)
			if err != nil {
				t.Fatalf("read replay: %v", err)
			}
			if !bytes.Equal(got, stream) {
				t.Fatal("replayed bytes differ from input")
			}
		})
	}
}

func TestPeekSNILargeClientHelloReplaysEntireStream(t *testing.T) {
	handshake := makeClientHello("large.example.com", 6000)
	if len(handshake) <= 4096 {
		t.Fatalf("test ClientHello is only %d bytes", len(handshake))
	}
	records := makeTLSRecords(handshake[:5000], 2000)
	lastPayload := append(append([]byte(nil), handshake[5000:]...), []byte("same-record tail")...)
	records = append(records, makeTLSRecord(0x16, lastPayload)...)
	stream := append(records, []byte("bytes after client hello")...)

	name, replay, err := PeekSNI(&fakeConn{r: bytes.NewReader(stream)}, 0)
	if err != nil {
		t.Fatalf("PeekSNI: %v", err)
	}
	if name != "large.example.com" {
		t.Fatalf("want large.example.com, got %q", name)
	}
	got, err := io.ReadAll(replay)
	if err != nil {
		t.Fatalf("read replay: %v", err)
	}
	if !bytes.Equal(got, stream) {
		t.Fatalf("replayed %d bytes, want exact %d-byte stream", len(got), len(stream))
	}
}

func TestPeekSNIRejectsMalformedRecordsAndLengths(t *testing.T) {
	handshake := makeClientHello("valid.example.com", 0)
	oversizedHello := []byte{
		0x01,
		byte((maxClientHelloLen >> 16) & 0xff),
		byte((maxClientHelloLen >> 8) & 0xff),
		byte(maxClientHelloLen & 0xff),
	}
	badExtensionsLen := append([]byte(nil), handshake...)
	badExtensionsLen[46]++
	badSNIListLen := append([]byte(nil), handshake...)
	badSNIListLen[52]++
	badSNINameLen := append([]byte(nil), handshake...)
	badSNINameLen[55]++
	shortSNINameLen := append([]byte(nil), handshake...)
	shortSNINameLen[55]--
	tooManyRecords := makeTLSRecords([]byte{0x01, 0, 1, 0}, 1, 2, 3)
	for range maxClientHelloRecords - 4 {
		tooManyRecords = append(tooManyRecords, makeTLSRecord(0x16, []byte{0})...)
	}

	tests := []struct {
		name    string
		stream  []byte
		wantErr string
	}{
		{name: "non-handshake first record", stream: makeTLSRecord(0x17, handshake), wantErr: "not a TLS handshake record"},
		{name: "non-handshake continuation", stream: append(makeTLSRecord(0x16, handshake[:2]), makeTLSRecord(0x17, handshake[2:])...), wantErr: "not a TLS handshake record"},
		{name: "empty record", stream: makeTLSRecord(0x16, nil), wantErr: "bad TLS record length 0"},
		{name: "oversized record", stream: []byte{0x16, 0x03, 0x01, 0x40, 0x01}, wantErr: "bad TLS record length 16385"},
		{name: "truncated record", stream: append([]byte{0x16, 0x03, 0x01, 0, 10}, []byte{1, 2, 3}...), wantErr: "read TLS record body"},
		{name: "oversized ClientHello", stream: makeTLSRecord(0x16, oversizedHello), wantErr: "exceeds limit"},
		{name: "truncated ClientHello", stream: makeTLSRecord(0x16, append([]byte{0x01, 0, 0, 100}, handshake[4:20]...)), wantErr: "read TLS record header"},
		{name: "too many records", stream: tooManyRecords, wantErr: "exceeds 64 TLS records"},
		{name: "bad extensions length", stream: makeTLSRecord(0x16, badExtensionsLen), wantErr: "bad extensions len"},
		{name: "bad SNI list length", stream: makeTLSRecord(0x16, badSNIListLen), wantErr: "bad SNI list len"},
		{name: "bad SNI name length", stream: makeTLSRecord(0x16, badSNINameLen), wantErr: "bad SNI name"},
		{name: "short SNI name length", stream: makeTLSRecord(0x16, shortSNINameLen), wantErr: "bad SNI name"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := PeekSNI(&fakeConn{r: bytes.NewReader(tt.stream)}, 0)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("PeekSNI error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestPeekSNIRejectsInvalidHostName(t *testing.T) {
	for _, host := range []string{"", "nul\x00.example.com"} {
		t.Run(host, func(t *testing.T) {
			stream := makeTLSRecords(makeClientHello(host, 0))
			if _, _, err := PeekSNI(&fakeConn{r: bytes.NewReader(stream)}, 0); err == nil {
				t.Fatal("PeekSNI accepted invalid host_name")
			}
		})
	}
}
