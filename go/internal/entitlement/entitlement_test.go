package entitlement

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blindport/blindport/internal/protocol"
)

const fixturePath = "../../../backend/tests/fixtures/offline_entitlement_v1.json"

type fixture struct {
	PublicKey string  `json:"public_key_b64url"`
	Payload   string  `json:"canonical_payload_b64url"`
	Artifact  string  `json:"artifact"`
	Signature string  `json:"signature_b64url"`
	Claims    payload `json:"claims"`
}

func TestVerifyFixture(t *testing.T) {
	data := loadFixture(t)
	rawPayload := mustDecode(t, data.Payload)
	publicKey := ed25519.PublicKey(mustDecode(t, data.PublicKey))
	signature := mustDecode(t, data.Signature)
	if !ed25519.Verify(publicKey, rawPayload, signature) {
		t.Fatal("fixture signature is invalid")
	}
	result, err := Verify(fixtureOptions(t, data))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Account != data.Claims.Account || result.Subscription != data.Claims.Subscription || result.Instance != data.Claims.Instance || result.Generation != data.Claims.Generation {
		t.Fatalf("verified identity = %+v", result)
	}
	if !result.PaidThrough.Equal(time.Unix(int64(data.Claims.PaidThrough), 0).UTC()) || !result.GraceThrough.Equal(time.Unix(int64(data.Claims.GraceThrough), 0).UTC()) || result.Status != StatusPaid {
		t.Fatalf("verified time state = %+v", result)
	}
	artifactParts := strings.Split(data.Artifact, ".")
	if len(artifactParts) != 3 || artifactParts[1] != data.Payload || artifactParts[2] != data.Signature {
		t.Fatal("fixture artifact does not preserve its exact payload and signature")
	}
}

func TestVerifyRejectsMalformedArtifacts(t *testing.T) {
	data := loadFixture(t)
	valid := fixtureOptions(t, data)
	tooLongPayload := "v1." + strings.Repeat("a", 1400) + "." + strings.Repeat("a", 86)
	tests := []struct {
		name     string
		artifact string
	}{
		{name: "empty", artifact: ""},
		{name: "wrong prefix", artifact: "v2.payload.signature"},
		{name: "missing segment", artifact: "v1.payload"},
		{name: "extra segment", artifact: data.Artifact + ".extra"},
		{name: "padding", artifact: strings.Replace(data.Artifact, ".", ".=", 1)},
		{name: "invalid alphabet", artifact: strings.Replace(data.Artifact, ".", ".*", 1)},
		{name: "non ascii", artifact: data.Artifact + "\u0080"},
		{name: "oversized decoded payload", artifact: tooLongPayload},
		{name: "oversized artifact", artifact: strings.Repeat("a", maxArtifactBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := valid
			options.Artifact = test.artifact
			if _, err := Verify(options); err == nil {
				t.Fatal("Verify() accepted malformed artifact")
			}
		})
	}
}

func TestVerifyRejectsNoncanonicalPayloads(t *testing.T) {
	data := loadFixture(t)
	raw := mustDecode(t, data.Payload)
	unknown := append([]byte(`{"unknown":0,`), raw[1:]...)
	reordered := bytes.Replace(raw, []byte(`{"typ":`), []byte(`{"v":1,"typ":`), 1)
	reordered = bytes.Replace(reordered, []byte(`,"v":1`), nil, 1)
	duplicate := bytes.Replace(raw, []byte(`"typ":`), []byte(`"typ":"blindport-offline-entitlement","typ":`), 1)
	whitespace := bytes.Replace(raw, []byte(`"typ":`), []byte(`"typ" :`), 1)
	noncanonicalNumber := bytes.Replace(raw, []byte(`"v":1`), []byte(`"v":1.0`), 1)
	trailing := append(append([]byte{}, raw...), ' ')
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "unknown field", raw: unknown},
		{name: "reordered fields", raw: reordered},
		{name: "duplicate field", raw: duplicate},
		{name: "whitespace", raw: whitespace},
		{name: "noncanonical number", raw: noncanonicalNumber},
		{name: "trailing whitespace", raw: trailing},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := fixtureOptions(t, data)
			options.Artifact = signedArtifact(t, test.raw)
			if _, err := Verify(options); err == nil {
				t.Fatal("Verify() accepted noncanonical payload")
			}
		})
	}
}

func TestVerifyRejectsPayloadValidationFailures(t *testing.T) {
	data := loadFixture(t)
	tests := []struct {
		name   string
		mutate func(*payload)
	}{
		{name: "bad type", mutate: func(value *payload) { value.Type = "other" }},
		{name: "bad version", mutate: func(value *payload) { value.Version = 2 }},
		{name: "uppercase key id", mutate: func(value *payload) { value.KeyID = "Offline-a" }},
		{name: "uppercase UUID", mutate: func(value *payload) { value.Account = strings.ToUpper(value.Account) }},
		{name: "invalid client key", mutate: func(value *payload) { value.ClientKey = strings.Repeat("a", 42) }},
		{name: "invalid token id", mutate: func(value *payload) { value.TokenID = strings.Repeat("a", 21) }},
		{name: "noncanonical IP", mutate: func(value *payload) { value.IP = "198.051.100.30" }},
		{name: "invalid port claim", mutate: func(value *payload) { value.Port = 0 }},
		{name: "unexpected port domain", mutate: func(value *payload) { value.Domain = "relay.example" }},
		{name: "relay transport", mutate: func(value *payload) {
			value.Kind, value.IP, value.Port, value.Transport, value.Domain = "relay", "", 0, "tcp", "relay.example"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := data.Claims
			test.mutate(&value)
			options := fixtureOptions(t, data)
			options.Artifact = signedPayload(t, value)
			if _, err := Verify(options); err == nil {
				t.Fatal("Verify() accepted invalid payload")
			}
		})
	}
}

func TestVerifyRejectsSignatureAndBindings(t *testing.T) {
	data := loadFixture(t)
	tests := []struct {
		name   string
		mutate func(*VerifyOptions)
	}{
		{name: "signature", mutate: func(options *VerifyOptions) { options.Artifact = options.Artifact[:len(options.Artifact)-1] + "A" }},
		{name: "key", mutate: func(options *VerifyOptions) {
			options.Keyring = map[string]ed25519.PublicKey{"offline-a": ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize)).Public().(ed25519.PublicKey)}
		}},
		{name: "edge", mutate: func(options *VerifyOptions) { options.Edge = "edge-b" }},
		{name: "claim", mutate: func(options *VerifyOptions) { options.Claim.Port++ }},
		{name: "client key", mutate: func(options *VerifyOptions) {
			options.ClientPublicKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := fixtureOptions(t, data)
			test.mutate(&options)
			if _, err := Verify(options); err == nil {
				t.Fatal("Verify() accepted mismatched binding")
			}
		})
	}
}

func TestVerifyTimeBoundaries(t *testing.T) {
	data := loadFixture(t)
	tests := []struct {
		name     string
		mutate   func(*payload)
		now      time.Time
		maxGrace time.Duration
		wantErr  bool
		status   Status
	}{
		{name: "paid boundary", now: time.Unix(int64(data.Claims.PaidThrough), 0), maxGrace: maxGrace, status: StatusPaid},
		{name: "grace boundary", now: time.Unix(int64(data.Claims.GraceThrough), 0), maxGrace: maxGrace, status: StatusGrace},
		{name: "after grace", now: time.Unix(int64(data.Claims.GraceThrough)+1, 0), maxGrace: maxGrace, wantErr: true},
		{name: "future skew accepted", mutate: func(value *payload) {
			value.IssuedAt, value.NotBefore, value.PaidThrough, value.GraceThrough = value.IssuedAt+60, value.NotBefore+60, value.PaidThrough+60, value.GraceThrough+60
			value.Generation = (value.PaidThrough << generationBits) | (value.Generation & maxCredentialNumber)
		}, now: time.Unix(int64(data.Claims.IssuedAt), 0), maxGrace: maxGrace, status: StatusPaid},
		{name: "future skew rejected", mutate: func(value *payload) { value.IssuedAt, value.NotBefore = value.IssuedAt+61, value.NotBefore+61 }, now: time.Unix(int64(data.Claims.IssuedAt), 0), maxGrace: maxGrace, wantErr: true},
		{name: "different nbf", mutate: func(value *payload) { value.NotBefore++ }, now: time.Unix(int64(data.Claims.IssuedAt), 0), maxGrace: maxGrace, wantErr: true},
		{name: "paid after grace", mutate: func(value *payload) { value.PaidThrough = value.GraceThrough + 1 }, now: time.Unix(int64(data.Claims.IssuedAt), 0), maxGrace: maxGrace, wantErr: true},
		{name: "excessive grace", mutate: func(value *payload) { value.GraceThrough = value.PaidThrough + uint64(maxGrace/time.Second) + 1 }, now: time.Unix(int64(data.Claims.IssuedAt), 0), maxGrace: maxGrace, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := data.Claims
			if test.mutate != nil {
				test.mutate(&value)
			}
			options := fixtureOptions(t, data)
			options.Artifact = signedPayload(t, value)
			options.Now = test.now
			options.MaxGrace = test.maxGrace
			result, err := Verify(options)
			if (err != nil) != test.wantErr {
				t.Fatalf("Verify() error = %v, wantErr %t", err, test.wantErr)
			}
			if err == nil && result.Status != test.status {
				t.Fatalf("status = %v, want %v", result.Status, test.status)
			}
		})
	}
}

func TestVerifyRejectsInvalidGenerationAndOptions(t *testing.T) {
	data := loadFixture(t)
	value := data.Claims
	value.Generation = (value.PaidThrough << generationBits)
	options := fixtureOptions(t, data)
	options.Artifact = signedPayload(t, value)
	if _, err := Verify(options); err == nil {
		t.Fatal("Verify() accepted zero credential generation")
	}
	value = data.Claims
	value.Generation = ((value.PaidThrough + 1) << generationBits) | (value.Generation & maxCredentialNumber)
	options = fixtureOptions(t, data)
	options.Artifact = signedPayload(t, value)
	if _, err := Verify(options); err == nil {
		t.Fatal("Verify() accepted a generation for another paid-through time")
	}
	options = fixtureOptions(t, data)
	options.MaxGrace = maxGrace + time.Second
	if _, err := Verify(options); err == nil {
		t.Fatal("Verify() accepted an excessive configured grace period")
	}
	options = fixtureOptions(t, data)
	options.Keyring["bad key"] = options.Keyring["offline-a"]
	if _, err := Verify(options); err == nil {
		t.Fatal("Verify() accepted a malformed supplied keyring")
	}
}

func TestCanonicalIPMatchesBackend(t *testing.T) {
	tests := map[string]string{
		"198.51.100.30":         "198.51.100.30",
		"2001:0db8:0:0:0:0:0:1": "2001:db8::1",
		"::ffff:198.51.100.30":  "::ffff:c633:641e",
	}
	for input, want := range tests {
		address, err := netip.ParseAddr(input)
		if err != nil {
			t.Fatalf("ParseAddr(%q): %v", input, err)
		}
		if got := canonicalIP(address); got != want {
			t.Errorf("canonicalIP(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestParseKeyring(t *testing.T) {
	data := loadFixture(t)
	valid := []byte(`{"offline-a":"` + data.PublicKey + `"}`)
	keys, err := ParseKeyring(valid)
	if err != nil || !bytes.Equal(keys["offline-a"], mustDecode(t, data.PublicKey)) {
		t.Fatalf("ParseKeyring() = %v, %v", keys, err)
	}
	tests := [][]byte{
		[]byte(`{ "offline-a":"` + data.PublicKey + `"}`),
		[]byte(`{"offline-a":"` + data.PublicKey + `","offline-a":"` + data.PublicKey + `"}`),
		[]byte(`{"Offline-a":"` + data.PublicKey + `"}`),
		[]byte(`{"offline-a":"` + data.PublicKey + `="}`),
		[]byte(`{"offline-a":"short"}`),
		[]byte(`[]`),
	}
	for _, input := range tests {
		if _, err := ParseKeyring(input); err == nil {
			t.Fatalf("ParseKeyring() accepted %q", input)
		}
	}
}

func TestDecodeRawBase64RejectsNonzeroTrailingBits(t *testing.T) {
	// Both strings decode with Go's non-strict decoder, but only "AA" is canonical.
	if decoded, err := decodeRawBase64("AA", 1); err != nil || !bytes.Equal(decoded, []byte{0}) {
		t.Fatalf("decodeRawBase64() = %x, %v", decoded, err)
	}
	if _, err := decodeRawBase64("AB", 1); err == nil {
		t.Fatal("decodeRawBase64() accepted noncanonical trailing bits")
	}
}

func FuzzVerify(f *testing.F) {
	data := loadFixtureForFuzz(f)
	f.Add(data.Artifact)
	f.Add("v1.invalid.invalid")
	f.Fuzz(func(t *testing.T, artifact string) {
		options := fixtureOptions(t, data)
		options.Artifact = artifact
		_, _ = Verify(options)
	})
}

func loadFixture(t testing.TB) fixture {
	t.Helper()
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var data fixture
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return data
}

func loadFixtureForFuzz(f *testing.F) fixture {
	f.Helper()
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		f.Fatalf("read fixture: %v", err)
	}
	var data fixture
	if err := json.Unmarshal(raw, &data); err != nil {
		f.Fatalf("decode fixture: %v", err)
	}
	return data
}

func fixtureOptions(t testing.TB, data fixture) VerifyOptions {
	t.Helper()
	keys, err := ParseKeyring([]byte(`{"offline-a":"` + data.PublicKey + `"}`))
	if err != nil {
		t.Fatalf("parse fixture keyring: %v", err)
	}
	return VerifyOptions{
		Artifact: data.Artifact,
		Keyring:  keys,
		Edge:     data.Claims.Edge,
		Claim: protocol.Claim{
			Kind: protocol.ClaimKind(data.Claims.Kind), IP: data.Claims.IP, Port: data.Claims.Port,
			Transport: protocol.Transport(data.Claims.Transport), Domain: data.Claims.Domain,
		},
		ClientPublicKey: ed25519.PublicKey(mustDecode(t, data.Claims.ClientKey)),
		Now:             time.Unix(int64(data.Claims.PaidThrough), 0),
		MaxGrace:        maxGrace,
	}
}

func signedPayload(t testing.TB, value payload) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return signedArtifact(t, raw)
}

func signedArtifact(t testing.TB, raw []byte) string {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	return artifactPrefix + "." + base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, raw))
}

func mustDecode(t testing.TB, value string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("decode base64url: %v", err)
	}
	return decoded
}
