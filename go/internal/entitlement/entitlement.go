// Package entitlement verifies signed offline entitlement artifacts.
package entitlement

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/blindport/blindport/internal/protocol"
)

const (
	artifactPrefix      = "v1"
	maxArtifactBytes    = 2048
	maxPayloadBytes     = 1024
	maxKeyringBytes     = 4096
	maxKeyringKeys      = 16
	maxIdentifierBytes  = 32
	maxGrace            = 7 * 24 * time.Hour
	generationBits      = 31
	maxUnixSeconds      = uint64((1<<63 - 1) >> generationBits)
	maxCredentialNumber = uint64(1<<generationBits - 1)
)

var stableID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)

// Status reports whether an entitlement remains paid or is using its grace period.
type Status uint8

const (
	StatusPaid Status = iota
	StatusGrace
)

// Verified is the identity and entitlement state authenticated by Verify.
type Verified struct {
	Account      string
	Subscription string
	Instance     string
	Generation   uint64
	PaidThrough  time.Time
	GraceThrough time.Time
	Status       Status
}

// VerifyOptions supplies all contextual bindings required to verify an artifact.
type VerifyOptions struct {
	Artifact        string
	Keyring         map[string]ed25519.PublicKey
	Edge            string
	Claim           protocol.Claim
	ClientPublicKey ed25519.PublicKey
	Now             time.Time
	MaxGrace        time.Duration
}

type payload struct {
	Type         string `json:"typ"`
	Version      uint64 `json:"v"`
	KeyID        string `json:"kid"`
	Account      string `json:"account"`
	Subscription string `json:"subscription"`
	Instance     string `json:"instance"`
	ClientKey    string `json:"client_pk"`
	Edge         string `json:"edge"`
	Kind         string `json:"kind"`
	IP           string `json:"ip"`
	Port         uint16 `json:"port"`
	Transport    string `json:"transport"`
	Domain       string `json:"domain"`
	IssuedAt     uint64 `json:"iat"`
	NotBefore    uint64 `json:"nbf"`
	PaidThrough  uint64 `json:"paid_through"`
	GraceThrough uint64 `json:"grace_through"`
	Generation   uint64 `json:"generation"`
	TokenID      string `json:"jti"`
}

// ParseKeyring parses a canonical JSON object of key IDs to raw Ed25519 keys.
func ParseKeyring(input []byte) (map[string]ed25519.PublicKey, error) {
	if !isASCII(input) || len(input) == 0 || len(input) > maxKeyringBytes {
		return nil, errors.New("invalid entitlement keyring")
	}
	var encoded map[string]string
	decoder := json.NewDecoder(strings.NewReader(string(input)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&encoded); err != nil {
		return nil, errors.New("invalid entitlement keyring")
	}
	if err := requireEOF(decoder); err != nil || len(encoded) == 0 || len(encoded) > maxKeyringKeys {
		return nil, errors.New("invalid entitlement keyring")
	}
	canonical, err := json.Marshal(encoded)
	if err != nil || string(canonical) != string(input) {
		return nil, errors.New("invalid entitlement keyring")
	}
	keys := make(map[string]ed25519.PublicKey, len(encoded))
	for keyID, value := range encoded {
		if !validStableID(keyID) {
			return nil, errors.New("invalid entitlement keyring")
		}
		key, err := decodeRawBase64(value, ed25519.PublicKeySize)
		if err != nil {
			return nil, errors.New("invalid entitlement keyring")
		}
		keys[keyID] = ed25519.PublicKey(key)
	}
	return keys, nil
}

// Verify checks the artifact signature, all contextual bindings, and its time bounds.
func Verify(options VerifyOptions) (*Verified, error) {
	if err := validateOptions(options); err != nil {
		return nil, err
	}
	rawPayload, signature, err := parseArtifact(options.Artifact)
	if err != nil {
		return nil, err
	}
	claim, err := decodePayload(rawPayload)
	if err != nil {
		return nil, err
	}
	key, ok := options.Keyring[claim.KeyID]
	if !ok || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, rawPayload, signature) {
		return nil, errors.New("invalid entitlement signature")
	}
	if err := validatePayload(claim); err != nil {
		return nil, err
	}
	if claim.Edge != options.Edge || !sameClaim(claim, options.Claim) {
		return nil, errors.New("entitlement binding mismatch")
	}
	clientKey, _ := decodeRawBase64(claim.ClientKey, ed25519.PublicKeySize)
	if !ed25519.PublicKey(clientKey).Equal(options.ClientPublicKey) {
		return nil, errors.New("entitlement binding mismatch")
	}
	return verifyTimes(claim, options.Now, options.MaxGrace)
}

func validateOptions(options VerifyOptions) error {
	if len(options.Keyring) == 0 || len(options.Keyring) > maxKeyringKeys || !validStableID(options.Edge) || len(options.ClientPublicKey) != ed25519.PublicKeySize || options.Now.IsZero() || options.MaxGrace < 0 || options.MaxGrace > maxGrace {
		return errors.New("invalid entitlement verification options")
	}
	for keyID, key := range options.Keyring {
		if !validStableID(keyID) || len(key) != ed25519.PublicKeySize {
			return errors.New("invalid entitlement verification options")
		}
	}
	if err := protocol.ValidateClaim(&options.Claim); err != nil {
		return errors.New("invalid entitlement verification options")
	}
	return nil
}

func parseArtifact(artifact string) ([]byte, []byte, error) {
	if len(artifact) == 0 || len(artifact) > maxArtifactBytes || !isASCII([]byte(artifact)) {
		return nil, nil, errors.New("invalid entitlement artifact")
	}
	parts := strings.Split(artifact, ".")
	if len(parts) != 3 || parts[0] != artifactPrefix {
		return nil, nil, errors.New("invalid entitlement artifact")
	}
	payloadBytes, err := decodeRawBase64(parts[1], -1)
	if err != nil || len(payloadBytes) == 0 || len(payloadBytes) > maxPayloadBytes {
		return nil, nil, errors.New("invalid entitlement artifact")
	}
	signature, err := decodeRawBase64(parts[2], ed25519.SignatureSize)
	if err != nil {
		return nil, nil, errors.New("invalid entitlement artifact")
	}
	return payloadBytes, signature, nil
}

func decodePayload(raw []byte) (payload, error) {
	if !isASCII(raw) {
		return payload{}, errors.New("invalid entitlement payload")
	}
	var value payload
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil || requireEOF(decoder) != nil {
		return payload{}, errors.New("invalid entitlement payload")
	}
	canonical, err := json.Marshal(value)
	if err != nil || string(canonical) != string(raw) {
		return payload{}, errors.New("invalid entitlement payload")
	}
	return value, nil
}

func validatePayload(value payload) error {
	if value.Type != "blindport-offline-entitlement" || value.Version != 1 || !validStableID(value.KeyID) || !validStableID(value.Edge) || !validUUID(value.Account) || !validUUID(value.Subscription) || !validUUID(value.Instance) || len(value.IP) > 45 || len(value.Domain) > 253 || len(value.ClientKey) != 43 || len(value.TokenID) != 22 {
		return errors.New("invalid entitlement payload")
	}
	if _, err := decodeRawBase64(value.ClientKey, ed25519.PublicKeySize); err != nil {
		return errors.New("invalid entitlement payload")
	}
	if _, err := decodeRawBase64(value.TokenID, 16); err != nil {
		return errors.New("invalid entitlement payload")
	}
	claim := protocol.Claim{Kind: protocol.ClaimKind(value.Kind), IP: value.IP, Port: value.Port, Transport: protocol.Transport(value.Transport), Domain: value.Domain}
	if err := protocol.ValidateClaim(&claim); err != nil || !canonicalClaim(value) {
		return errors.New("invalid entitlement payload")
	}
	return nil
}

func canonicalClaim(value payload) bool {
	switch protocol.ClaimKind(value.Kind) {
	case protocol.ClaimIP, protocol.ClaimPort:
		address, err := netip.ParseAddr(value.IP)
		if err != nil || canonicalIP(address) != value.IP {
			return false
		}
	case protocol.ClaimRelay:
		if value.IP != "" {
			return false
		}
	}
	return (value.Kind != string(protocol.ClaimIP) || value.Transport == "") && (value.Kind != string(protocol.ClaimRelay) || value.Transport == "")
}

func canonicalIP(address netip.Addr) string {
	if address.Is4() {
		return address.String()
	}
	bytes := address.As16()
	groups := [8]uint16{}
	for index := range groups {
		groups[index] = uint16(bytes[index*2])<<8 | uint16(bytes[index*2+1])
	}
	bestStart, bestLength := -1, 0
	for index := 0; index < len(groups); {
		if groups[index] != 0 {
			index++
			continue
		}
		end := index
		for end < len(groups) && groups[end] == 0 {
			end++
		}
		if end-index > bestLength {
			bestStart, bestLength = index, end-index
		}
		index = end
	}
	if bestLength < 2 {
		bestStart = -1
	}
	var builder strings.Builder
	for index := 0; index < len(groups); {
		if index == bestStart {
			builder.WriteString("::")
			index += bestLength
			continue
		}
		if builder.Len() > 0 && !strings.HasSuffix(builder.String(), ":") {
			builder.WriteByte(':')
		}
		builder.WriteString(strconv.FormatUint(uint64(groups[index]), 16))
		index++
	}
	return builder.String()
}

func sameClaim(value payload, expected protocol.Claim) bool {
	return value.Kind == string(expected.Kind) && value.IP == expected.IP && value.Port == expected.Port && value.Transport == string(expected.Transport) && value.Domain == expected.Domain
}

func verifyTimes(value payload, now time.Time, allowedGrace time.Duration) (*Verified, error) {
	if value.IssuedAt > maxUnixSeconds || value.NotBefore > maxUnixSeconds || value.PaidThrough > maxUnixSeconds || value.GraceThrough > maxUnixSeconds || value.IssuedAt != value.NotBefore || value.IssuedAt > value.PaidThrough || value.PaidThrough > value.GraceThrough || value.GraceThrough-value.PaidThrough > uint64(allowedGrace/time.Second) {
		return nil, errors.New("invalid entitlement times")
	}
	low := value.Generation & maxCredentialNumber
	if value.Generation > uint64(1<<63-1) || low == 0 || value.Generation != (value.PaidThrough<<generationBits)|low {
		return nil, errors.New("invalid entitlement generation")
	}
	issuedAt := time.Unix(int64(value.IssuedAt), 0).UTC()
	paidThrough := time.Unix(int64(value.PaidThrough), 0).UTC()
	graceThrough := time.Unix(int64(value.GraceThrough), 0).UTC()
	current := now.UTC()
	if issuedAt.After(current.Add(60*time.Second)) || current.After(graceThrough) {
		return nil, errors.New("entitlement is not currently valid")
	}
	status := StatusPaid
	if current.After(paidThrough) {
		status = StatusGrace
	}
	return &Verified{Account: value.Account, Subscription: value.Subscription, Instance: value.Instance, Generation: value.Generation, PaidThrough: paidThrough, GraceThrough: graceThrough, Status: status}, nil
}

func validStableID(value string) bool {
	return len(value) <= maxIdentifierBytes && stableID.MatchString(value)
}

func validUUID(value string) bool {
	if len(value) != 36 || !isASCII([]byte(value)) {
		return false
	}
	for index := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if value[index] != '-' {
				return false
			}
			continue
		}
		if !(value[index] >= '0' && value[index] <= '9' || value[index] >= 'a' && value[index] <= 'f') {
			return false
		}
	}
	return true
}

func decodeRawBase64(value string, length int) ([]byte, error) {
	if value == "" || strings.Contains(value, "=") {
		return nil, errors.New("invalid base64url")
	}
	for index := range value {
		if !(value[index] >= 'A' && value[index] <= 'Z' || value[index] >= 'a' && value[index] <= 'z' || value[index] >= '0' && value[index] <= '9' || value[index] == '-' || value[index] == '_') {
			return nil, errors.New("invalid base64url")
		}
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value || (length >= 0 && len(decoded) != length) {
		return nil, errors.New("invalid base64url")
	}
	return decoded, nil
}

func isASCII(value []byte) bool {
	for _, character := range value {
		if character > 0x7f {
			return false
		}
	}
	return true
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}
