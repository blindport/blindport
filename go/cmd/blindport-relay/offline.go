package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/blindport/blindport/internal/entitlement"
	"github.com/blindport/blindport/internal/protocol"
)

const maxOfflineEntitlementGrace = 7 * 24 * time.Hour

type offlineEntitlementConfig struct {
	keyring  map[string]ed25519.PublicKey
	maxGrace time.Duration
	edgeID   string
}

type offlineAuthorization struct {
	artifact string
	identity clientIdentity
}

func parseOfflineEntitlementConfig(enabled bool, keyringJSON, edgeID string, maxGraceSeconds int) (*offlineEntitlementConfig, error) {
	if !enabled {
		return nil, nil
	}
	if maxGraceSeconds < 1 || maxGraceSeconds > int(maxOfflineEntitlementGrace/time.Second) {
		return nil, fmt.Errorf("offline entitlement maximum grace must be within 1-604800 seconds")
	}
	keyring, err := entitlement.ParseKeyring([]byte(keyringJSON))
	if err != nil {
		return nil, fmt.Errorf("invalid offline entitlement public keys")
	}
	if _, err := validateOfflineEdgeID(edgeID); err != nil {
		return nil, err
	}
	return &offlineEntitlementConfig{
		keyring: keyring, maxGrace: time.Duration(maxGraceSeconds) * time.Second, edgeID: edgeID,
	}, nil
}

func validateOfflineEdgeID(edgeID string) (string, error) {
	if edgeID == "" || len(edgeID) > 32 {
		return "", fmt.Errorf("invalid relay edge ID")
	}
	for index := range edgeID {
		character := edgeID[index]
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '.' || character == '_' || character == '-') {
			return "", fmt.Errorf("invalid relay edge ID")
		}
	}
	if edgeID[0] == '.' || edgeID[0] == '_' || edgeID[0] == '-' {
		return "", fmt.Errorf("invalid relay edge ID")
	}
	return edgeID, nil
}

func offlineCertificateIdentity(state tls.ConnectionState) (clientIdentity, error) {
	identity, err := certificateIdentity(state)
	if err != nil {
		return clientIdentity{}, err
	}
	if identity.kind != clientIdentityAccount || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return clientIdentity{}, fmt.Errorf("offline entitlements require a v2 account certificate")
	}
	certificate := state.VerifiedChains[0][0]
	if len(certificate.URIs) != 1 || certificate.URIs[0] == nil {
		return clientIdentity{}, fmt.Errorf("offline entitlements require one instance URI SAN")
	}
	uri := certificate.URIs[0]
	const prefix = "urn:blindport:client:"
	rawURI := uri.String()
	if !strings.HasPrefix(rawURI, prefix) {
		return clientIdentity{}, fmt.Errorf("offline entitlement instance URI SAN is invalid")
	}
	instanceID, err := parseCanonicalUUID(strings.TrimPrefix(rawURI, prefix))
	if err != nil {
		return clientIdentity{}, fmt.Errorf("offline entitlement instance URI SAN is invalid")
	}
	publicKey, ok := certificate.PublicKey.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return clientIdentity{}, fmt.Errorf("offline entitlements require an Ed25519 client key")
	}
	identity.instanceID = instanceID
	identity.clientPublicKey = append([]byte(nil), publicKey...)
	identity.offlineV2 = true
	return identity, nil
}

func (r *relay) verifyOfflineEntitlement(artifact string, claim *protocol.Claim, identity clientIdentity, now time.Time) (*entitlement.Verified, error) {
	if r.offlineEntitlements == nil || !identity.offlineV2 || claim == nil {
		return nil, fmt.Errorf("offline entitlement is unavailable")
	}
	verified, err := entitlement.Verify(entitlement.VerifyOptions{
		Artifact: artifact, Keyring: r.offlineEntitlements.keyring, Edge: r.offlineEntitlements.edgeID,
		Claim: *claim, ClientPublicKey: ed25519.PublicKey(identity.clientPublicKey), Now: now, MaxGrace: r.offlineEntitlements.maxGrace,
	})
	if err != nil {
		return nil, err
	}
	accountID, err := parseCanonicalUUID(verified.Account)
	if err != nil || accountID != identity.accountID {
		return nil, fmt.Errorf("offline entitlement account does not match certificate")
	}
	instanceID, err := parseCanonicalUUID(verified.Instance)
	if err != nil || instanceID != identity.instanceID {
		return nil, fmt.Errorf("offline entitlement instance does not match certificate")
	}
	return verified, nil
}
