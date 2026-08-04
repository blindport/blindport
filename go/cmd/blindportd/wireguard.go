package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/blindport/blindport/internal/wgnet"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	wireGuardStateVersion    = 1
	wireGuardStateName       = "wireguard.json"
	maxWireGuardStateSize    = 4 << 10
	maxWireGuardResponseSize = 64 << 10
	maxLinuxRoutingID        = 1<<31 - 1
)

type storedWireGuardKey struct {
	Version    int    `json:"version"`
	PrivateKey string `json:"private_key"`
}

// wireGuardConfigV2 mirrors GET /api/v2/client/wireguard exactly.
type wireGuardConfigV2 struct {
	InstanceID                 string   `json:"instance_id"`
	Generation                 int      `json:"generation"`
	PublicKey                  *string  `json:"public_key"`
	AssignedPrefixes           []string `json:"assigned_prefixes"`
	RelayPublicKey             string   `json:"relay_public_key"`
	Endpoint                   string   `json:"endpoint"`
	MTU                        int      `json:"mtu"`
	PersistentKeepaliveSeconds int      `json:"persistent_keepalive_seconds"`
}

type wireGuardKeyRequestV2 struct {
	InstanceID string `json:"instance_id"`
	Generation int    `json:"generation"`
	PublicKey  string `json:"public_key"`
	Signature  string `json:"signature"`
}

// wireGuardEnrollmentMessage must match the backend signature format exactly.
func wireGuardEnrollmentMessage(instanceID string, generation int, publicKey string) []byte {
	return []byte(fmt.Sprintf(
		"blindport-wireguard-key-v1\ninstance_id=%s\ngeneration=%d\npublic_key=%s\n",
		instanceID, generation, publicKey,
	))
}

func loadOrCreateAgentWireGuardKey(stateDir string) (wgtypes.Key, error) {
	statePath := filepath.Join(stateDir, wireGuardStateName)
	file, err := openStaticConfig(statePath)
	if err == nil {
		defer file.Close()
		info, statErr := file.Stat()
		if statErr != nil {
			return wgtypes.Key{}, fmt.Errorf("inspect WireGuard state: %w", statErr)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return wgtypes.Key{}, errors.New("WireGuard state must be a regular owner-only file")
		}
		if ownerErr := validateStaticConfigOwner(info); ownerErr != nil {
			return wgtypes.Key{}, fmt.Errorf("WireGuard state: %w", ownerErr)
		}
		data, readErr := io.ReadAll(io.LimitReader(file, maxWireGuardStateSize+1))
		if readErr != nil {
			return wgtypes.Key{}, fmt.Errorf("read WireGuard state: %w", readErr)
		}
		if len(data) > maxWireGuardStateSize {
			return wgtypes.Key{}, fmt.Errorf("WireGuard state exceeds %d bytes", maxWireGuardStateSize)
		}
		var stored storedWireGuardKey
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if decodeErr := decoder.Decode(&stored); decodeErr != nil {
			return wgtypes.Key{}, fmt.Errorf("decode WireGuard state: %w", decodeErr)
		}
		if trailingErr := rejectTrailingJSON(decoder); trailingErr != nil {
			return wgtypes.Key{}, fmt.Errorf("decode WireGuard state: %w", trailingErr)
		}
		if stored.Version != wireGuardStateVersion {
			return wgtypes.Key{}, fmt.Errorf("unsupported WireGuard state version %d", stored.Version)
		}
		key, parseErr := wgtypes.ParseKey(stored.PrivateKey)
		if parseErr != nil {
			return wgtypes.Key{}, fmt.Errorf("parse persisted WireGuard key: %w", parseErr)
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return wgtypes.Key{}, err
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("generate WireGuard key: %w", err)
	}
	if err := writeAgentWireGuardKey(stateDir, statePath, key); err != nil {
		return wgtypes.Key{}, err
	}
	return key, nil
}

func writeAgentWireGuardKey(stateDir, statePath string, key wgtypes.Key) error {
	data, err := json.MarshalIndent(storedWireGuardKey{
		Version:    wireGuardStateVersion,
		PrivateKey: key.String(),
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode WireGuard state: %w", err)
	}
	data = append(data, '\n')
	temporary, err := os.CreateTemp(stateDir, ".wireguard-*")
	if err != nil {
		return fmt.Errorf("create temporary WireGuard state: %w", err)
	}
	temporaryPath := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}
	if err := temporary.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("protect temporary WireGuard state: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write temporary WireGuard state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync temporary WireGuard state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temporary WireGuard state: %w", err)
	}
	if err := os.Rename(temporaryPath, statePath); err != nil {
		cleanup()
		return fmt.Errorf("replace WireGuard state: %w", err)
	}
	directory, err := os.Open(stateDir)
	if err != nil {
		return fmt.Errorf("open state directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync state directory: %w", err)
	}
	return nil
}

func fetchWireGuardConfig(ctx context.Context, client *http.Client, backend, token string) (*wireGuardConfigV2, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, backend+"/api/v2/client/wireguard", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch WireGuard config: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("WireGuard config status %d", resp.StatusCode)
	}
	var config wireGuardConfigV2
	if err := decodeBoundedJSON(resp.Body, maxWireGuardResponseSize, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func enrollWireGuardKey(ctx context.Context, client *http.Client, backend, token string, request wireGuardKeyRequestV2) (*wireGuardConfigV2, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("encode WireGuard key request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, backend+"/api/v2/client/wireguard/key", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("enroll WireGuard key: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("WireGuard key status %d", resp.StatusCode)
	}
	var config wireGuardConfigV2
	if err := decodeBoundedJSON(resp.Body, maxWireGuardResponseSize, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func validateWireGuardClientConfig(config *wireGuardConfigV2, publicKey string) error {
	if config.PublicKey == nil || *config.PublicKey != publicKey {
		return errors.New("backend did not confirm the local WireGuard key")
	}
	if err := wgnet.ValidateKey(config.RelayPublicKey); err != nil {
		return fmt.Errorf("relay public key: %w", err)
	}
	if err := validateHostPort(config.Endpoint); err != nil {
		return fmt.Errorf("relay endpoint: %w", err)
	}
	if len(config.AssignedPrefixes) == 0 {
		return errors.New("no routed prefixes are assigned")
	}
	for _, prefix := range config.AssignedPrefixes {
		if _, err := wgnet.ValidatePrefix(prefix); err != nil {
			return err
		}
	}
	if config.MTU < 1280 || config.MTU > 1420 {
		return fmt.Errorf("MTU %d is outside 1280-1420", config.MTU)
	}
	if config.PersistentKeepaliveSeconds < 0 || config.PersistentKeepaliveSeconds > 120 {
		return fmt.Errorf("keepalive %d is outside 0-120 seconds", config.PersistentKeepaliveSeconds)
	}
	return nil
}

type wireGuardAgentOptions struct {
	backendURL   string
	token        string
	httpClient   *http.Client
	stateDir     string
	deviceName   string
	routeTable   int
	rulePriority int
}

func validateWireGuardAgentOptions(options wireGuardAgentOptions) error {
	if options.httpClient == nil {
		return errors.New("WireGuard HTTP client is required")
	}
	if options.routeTable < 1 || options.routeTable > maxLinuxRoutingID ||
		options.rulePriority < 1 || options.rulePriority > maxLinuxRoutingID {
		return fmt.Errorf("WireGuard route table and rule priority must be within 1-%d", maxLinuxRoutingID)
	}
	return nil
}

// runWireGuard enrolls the local peer key and applies the routed plane, then
// blocks until shutdown. Provisioning is startup-only, like framed mappings.
func runWireGuard(ctx context.Context, log *slog.Logger, credentials *credentialManager, options wireGuardAgentOptions) error {
	if err := validateWireGuardAgentOptions(options); err != nil {
		return err
	}
	key, err := loadOrCreateAgentWireGuardKey(options.stateDir)
	if err != nil {
		return err
	}
	publicKey := key.PublicKey().String()
	config, err := fetchWireGuardConfig(ctx, options.httpClient, options.backendURL, options.token)
	if err != nil {
		return err
	}
	if config.PublicKey == nil || *config.PublicKey != publicKey {
		generation := config.Generation + 1
		message := wireGuardEnrollmentMessage(credentials.instanceID(), generation, publicKey)
		request := wireGuardKeyRequestV2{
			InstanceID: credentials.instanceID(),
			Generation: generation,
			PublicKey:  publicKey,
			Signature:  base64.StdEncoding.EncodeToString(credentials.signMessage(message)),
		}
		config, err = enrollWireGuardKey(ctx, options.httpClient, options.backendURL, options.token, request)
		if err != nil {
			return err
		}
	}
	if err := validateWireGuardClientConfig(config, publicKey); err != nil {
		return fmt.Errorf("invalid WireGuard provisioning: %w", err)
	}
	if options.rulePriority > maxLinuxRoutingID-len(config.AssignedPrefixes)+1 {
		return errors.New("WireGuard rule priorities exceed the Linux routing range")
	}
	if err := wgnet.ConfigureAgent(wgnet.AgentConfig{
		DeviceName:          options.deviceName,
		PrivateKey:          key,
		RelayPublicKey:      config.RelayPublicKey,
		Endpoint:            config.Endpoint,
		MTU:                 config.MTU,
		Prefixes:            config.AssignedPrefixes,
		PersistentKeepalive: time.Duration(config.PersistentKeepaliveSeconds) * time.Second,
		RouteTable:          options.routeTable,
		RulePriority:        options.rulePriority,
	}); err != nil {
		return err
	}
	log.Info("routed WireGuard plane configured",
		"device", options.deviceName,
		"prefixes", config.AssignedPrefixes,
		"endpoint", config.Endpoint,
		"mtu", config.MTU)
	<-ctx.Done()
	return nil
}
