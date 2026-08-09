package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

func TestFrameRoundtrip(t *testing.T) {
	cases := []*Frame{
		{Type: TypeHello, Token: "ABC123", Entitlement: "v1.payload.signature", Claim: &Claim{Kind: ClaimIP, IP: "1.2.3.4"}},
		{Type: TypeHello, Token: "ABC123", Claim: &Claim{Kind: ClaimPort, IP: "1.2.3.4", Port: 10000, Transport: TransportTCP}},
		{Type: TypeOpen, Stream: 7, Proto: "tcp", Src: "9.9.9.9:1", Dst: "1.2.3.4:443"},
		{Type: TypeData, Stream: 7, Data: []byte("hello world")},
		{Type: TypeDatagram, Stream: 8, Data: []byte("one packet")},
		{Type: TypeWindowUpdate, Stream: 7, Credit: 4096},
		{Type: TypeCloseWrite, Stream: 7},
		{Type: TypeClose, Stream: 7},
		{Type: TypeHelloOK, Capabilities: []Capability{CapabilityTCPHalfClose, CapabilityStreamFlowControl}},
	}
	for _, f := range cases {
		var buf bytes.Buffer
		if err := WriteFrame(&buf, f); err != nil {
			t.Fatalf("write: %v", err)
		}
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if got.Type != f.Type || got.Stream != f.Stream || got.Token != f.Token || got.Entitlement != f.Entitlement || got.Credit != f.Credit {
			t.Errorf("mismatch: %+v vs %+v", got, f)
		}
		if !bytes.Equal(got.Data, f.Data) {
			t.Errorf("data mismatch: %q vs %q", got.Data, f.Data)
		}
	}
}

func TestFrameCapabilities(t *testing.T) {
	frame := &Frame{Capabilities: []Capability{"future", CapabilityTCPHalfClose, CapabilityStreamFlowControl, CapabilityOfflineEntitlementV1}}
	if !frame.HasCapability(CapabilityTCPHalfClose) {
		t.Fatal("advertised TCP half-close capability not found")
	}
	if frame.HasCapability("missing") {
		t.Fatal("unadvertised capability found")
	}
	if !frame.HasCapability(CapabilityStreamFlowControl) {
		t.Fatal("advertised stream flow-control capability not found")
	}
	if !frame.HasCapability(CapabilityOfflineEntitlementV1) {
		t.Fatal("advertised offline entitlement capability not found")
	}
}

func TestHelloEntitlementSizeLimit(t *testing.T) {
	var buf bytes.Buffer
	frame := &Frame{Type: TypeHello, Entitlement: strings.Repeat("x", MaxHelloFrameSize)}
	if err := WriteFrame(&buf, frame); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}
	if _, err := ReadFrameWithLimit(&buf, MaxHelloFrameSize); err == nil {
		t.Fatal("ReadFrameWithLimit() accepted an oversized entitlement Hello")
	}
}

func TestValidateClaim(t *testing.T) {
	tests := []struct {
		name    string
		claim   *Claim
		wantErr bool
	}{
		{name: "ip", claim: &Claim{Kind: ClaimIP, IP: "203.0.113.10"}},
		{name: "ip tcp", claim: &Claim{Kind: ClaimIP, IP: "203.0.113.10", Transport: TransportTCP}},
		{name: "port", claim: &Claim{Kind: ClaimPort, IP: "203.0.113.20", Port: 10000, Transport: TransportTCP}},
		{name: "relay", claim: &Claim{Kind: ClaimRelay, Domain: "alice.example"}},
		{name: "nil", wantErr: true},
		{name: "unknown", claim: &Claim{Kind: "udp", IP: "203.0.113.10"}, wantErr: true},
		{name: "ip port", claim: &Claim{Kind: ClaimIP, IP: "203.0.113.10", Port: 80}, wantErr: true},
		{name: "port no port", claim: &Claim{Kind: ClaimPort, IP: "203.0.113.20", Transport: TransportTCP}, wantErr: true},
		{name: "port no transport", claim: &Claim{Kind: ClaimPort, IP: "203.0.113.20", Port: 10000}, wantErr: true},
		{name: "port udp", claim: &Claim{Kind: ClaimPort, IP: "203.0.113.20", Port: 10000, Transport: TransportUDP}},
		{name: "port domain", claim: &Claim{Kind: ClaimPort, IP: "203.0.113.20", Port: 10000, Transport: TransportTCP, Domain: "bad.example"}, wantErr: true},
		{name: "relay uppercase", claim: &Claim{Kind: ClaimRelay, Domain: "Alice.Example"}, wantErr: true},
		{name: "relay ip", claim: &Claim{Kind: ClaimRelay, Domain: "127.0.0.1"}, wantErr: true},
		{name: "relay wildcard", claim: &Claim{Kind: ClaimRelay, Domain: "public.example", Scope: RelayHostnameScopeWildcard}},
		{name: "relay wildcard marker", claim: &Claim{Kind: ClaimRelay, Domain: "*.public.example", Scope: RelayHostnameScopeWildcard}, wantErr: true},
		{name: "relay unsupported scope", claim: &Claim{Kind: ClaimRelay, Domain: "public.example", Scope: "exact"}, wantErr: true},
		{name: "ip scope", claim: &Claim{Kind: ClaimIP, IP: "203.0.113.10", Scope: RelayHostnameScopeWildcard}, wantErr: true},
		{name: "port scope", claim: &Claim{Kind: ClaimPort, IP: "203.0.113.20", Port: 10000, Transport: TransportTCP, Scope: RelayHostnameScopeWildcard}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateClaim(tt.claim)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateClaim() error = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}

func TestRelayClaimScopeJSONCompatibility(t *testing.T) {
	exact, err := json.Marshal(Claim{Kind: ClaimRelay, Domain: "public.example"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(exact), `{"kind":"relay","domain":"public.example"}`; got != want {
		t.Fatalf("exact claim JSON = %s, want %s", got, want)
	}
	wildcard, err := json.Marshal(Claim{Kind: ClaimRelay, Domain: "public.example", Scope: RelayHostnameScopeWildcard})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(wildcard), `{"kind":"relay","domain":"public.example","scope":"wildcard"}`; got != want {
		t.Fatalf("wildcard claim JSON = %s, want %s", got, want)
	}
}

func TestUDPRequiresCurrentProtocolVersion(t *testing.T) {
	udp := &Claim{Kind: ClaimPort, IP: "203.0.113.20", Port: 10000, Transport: TransportUDP}
	if err := ValidateVersion(0, udp); err == nil {
		t.Fatal("legacy protocol version accepted UDP")
	}
	if err := ValidateVersion(CurrentVersion, udp); err != nil {
		t.Fatalf("current protocol version rejected UDP: %v", err)
	}
	if err := ValidateVersion(CurrentVersion+1, &Claim{Kind: ClaimIP, IP: "203.0.113.10"}); err == nil {
		t.Fatal("future protocol version accepted")
	}
}

func TestDataPayloadLimit(t *testing.T) {
	maxPayload := bytes.Repeat([]byte{'a'}, MaxDataPayloadSize)
	var buf bytes.Buffer
	if err := WriteFrame(&buf, &Frame{Type: TypeData, Stream: 1, Data: maxPayload}); err != nil {
		t.Fatalf("write maximum payload: %v", err)
	}
	if _, err := ReadFrame(&buf); err != nil {
		t.Fatalf("read maximum payload: %v", err)
	}

	tooLarge := append(maxPayload, 'b')
	if err := WriteFrame(&buf, &Frame{Type: TypeData, Stream: 1, Data: tooLarge}); err == nil || !strings.Contains(err.Error(), "data payload too large") {
		t.Fatalf("write oversized payload error = %v", err)
	}

	encoded, err := json.Marshal(&Frame{Type: TypeData, Stream: 1, Data: tooLarge})
	if err != nil {
		t.Fatalf("marshal oversized frame: %v", err)
	}
	buf.Reset()
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(encoded))); err != nil {
		t.Fatalf("write frame header: %v", err)
	}
	if _, err := buf.Write(encoded); err != nil {
		t.Fatalf("write frame body: %v", err)
	}
	if _, err := ReadFrame(&buf); err == nil || !strings.Contains(err.Error(), "data payload too large") {
		t.Fatalf("read oversized payload error = %v", err)
	}
}

func TestDatagramPayloadLimit(t *testing.T) {
	maxPayload := bytes.Repeat([]byte{'u'}, MaxDatagramPayloadSize)
	var buf bytes.Buffer
	if err := WriteFrame(&buf, &Frame{Type: TypeDatagram, Stream: 1, Data: maxPayload}); err != nil {
		t.Fatalf("write maximum datagram: %v", err)
	}
	frame, err := ReadFrame(&buf)
	if err != nil || !bytes.Equal(frame.Data, maxPayload) {
		t.Fatalf("read maximum datagram: %v", err)
	}
	tooLarge := append(maxPayload, 'x')
	if err := WriteFrame(&buf, &Frame{Type: TypeDatagram, Stream: 1, Data: tooLarge}); err == nil || !strings.Contains(err.Error(), "datagram payload too large") {
		t.Fatalf("write oversized datagram error = %v", err)
	}
}

func TestReadFrameWithLimit(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, &Frame{Type: TypeHello, Token: strings.Repeat("x", 128)}); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}
	if _, err := ReadFrameWithLimit(&buf, 64); err == nil || !strings.Contains(err.Error(), "frame too large") {
		t.Fatalf("ReadFrameWithLimit() error = %v", err)
	}

	buf.Reset()
	if err := WriteFrame(&buf, &Frame{Type: TypeHello, Token: strings.Repeat("x", MaxHelloFrameSize)}); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}
	if _, err := ReadFrameWithLimit(&buf, MaxHelloFrameSize); err == nil {
		t.Fatal("ReadFrameWithLimit() accepted an oversized HELLO")
	}

	buf.Reset()
	if err := WriteFrame(&buf, &Frame{Type: TypeData, Stream: 1, Data: bytes.Repeat([]byte{'x'}, MaxDataPayloadSize)}); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}
	if _, err := ReadFrame(&buf); err != nil {
		t.Fatalf("ReadFrame() no longer accepts normal 1 MiB-capped frames: %v", err)
	}
}
