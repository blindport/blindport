package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/blindport/blindport/internal/relayauth"
)

const (
	certificateCacheFileName = "certificate.json"
	certificateCacheVersion  = 1
	maxCertificateCacheSize  = 64 << 10
)

type certificateCache struct {
	dir string
}

type certificateCacheEnvelope struct {
	Version     int                 `json:"version"`
	Hostnames   []string            `json:"hostnames"`
	IPs         []string            `json:"ips"`
	Certificate relayauth.RelayCert `json:"certificate"`
}

func newCertificateCache(dir string) *certificateCache {
	if dir == "" {
		return nil
	}
	return &certificateCache{dir: dir}
}

func canonicalCertificateIdentities(hosts, ips []string) ([]string, []string, error) {
	canonicalHosts := make([]string, 0, len(hosts))
	hostSeen := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		canonical := strings.ToLower(strings.TrimSuffix(host, "."))
		if canonical == "" || strings.HasSuffix(canonical, ".") {
			return nil, nil, fmt.Errorf("invalid certificate hostname %q", host)
		}
		if _, ok := hostSeen[canonical]; ok {
			return nil, nil, fmt.Errorf("duplicate certificate hostname %q", host)
		}
		hostSeen[canonical] = struct{}{}
		canonicalHosts = append(canonicalHosts, canonical)
	}

	canonicalIPs := make([]string, 0, len(ips))
	ipSeen := make(map[string]struct{}, len(ips))
	for _, rawIP := range ips {
		parsed := net.ParseIP(rawIP)
		if parsed == nil {
			return nil, nil, fmt.Errorf("invalid requested certificate IP %q", rawIP)
		}
		canonical := parsed.String()
		if _, ok := ipSeen[canonical]; ok {
			return nil, nil, fmt.Errorf("duplicate certificate IP %q", rawIP)
		}
		ipSeen[canonical] = struct{}{}
		canonicalIPs = append(canonicalIPs, canonical)
	}
	if len(canonicalHosts) == 0 && len(canonicalIPs) == 0 {
		return nil, nil, errors.New("no hostnames or IPs given for relay server certificate")
	}
	sort.Strings(canonicalHosts)
	sort.Strings(canonicalIPs)
	return canonicalHosts, canonicalIPs, nil
}

func (c *certificateCache) load(hosts, ips []string, now time.Time) (*tlsCertificateMaterial, error) {
	dir, err := c.prepareDirectory()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, certificateCacheFileName)
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect cache file: %w", err)
	}
	if err := validateCertificateCacheFile(before); err != nil {
		return nil, err
	}
	f, err := openCertificateCacheFile(path)
	if err != nil {
		return nil, fmt.Errorf("open cache file: %w", err)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened cache file: %w", err)
	}
	if !os.SameFile(before, opened) {
		return nil, errors.New("cache file changed while opening")
	}
	if err := validateCertificateCacheFile(opened); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxCertificateCacheSize+1))
	if err != nil {
		return nil, fmt.Errorf("read cache file: %w", err)
	}
	if len(data) > maxCertificateCacheSize {
		return nil, fmt.Errorf("cache file exceeds %d bytes", maxCertificateCacheSize)
	}
	envelope, err := decodeCertificateCache(data)
	if err != nil {
		return nil, err
	}
	expectedHosts, expectedIPs, err := canonicalCertificateIdentities(hosts, ips)
	if err != nil {
		return nil, err
	}
	if !equalStrings(envelope.Hostnames, expectedHosts) || !equalStrings(envelope.IPs, expectedIPs) {
		return nil, errors.New("cache identities do not match configured identities")
	}
	cert, ca, pool, err := validateCertificateResponse(&envelope.Certificate, expectedHosts, expectedIPs, nil, now)
	if err != nil {
		return nil, fmt.Errorf("validate cached certificate: %w", err)
	}
	return &tlsCertificateMaterial{cert: cert, ca: ca, pool: pool}, nil
}

func (c *certificateCache) store(response *relayauth.RelayCert, hosts, ips []string, now time.Time) error {
	canonicalHosts, canonicalIPs, err := canonicalCertificateIdentities(hosts, ips)
	if err != nil {
		return err
	}
	if _, _, _, err := validateCertificateResponse(response, canonicalHosts, canonicalIPs, nil, now); err != nil {
		return fmt.Errorf("validate certificate before caching: %w", err)
	}
	dir, err := c.prepareDirectory()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, certificateCacheFileName)
	payload, err := json.Marshal(certificateCacheEnvelope{
		Version: certificateCacheVersion, Hostnames: canonicalHosts, IPs: canonicalIPs, Certificate: *response,
	})
	if err != nil {
		return fmt.Errorf("encode certificate cache: %w", err)
	}
	if len(payload) > maxCertificateCacheSize {
		return fmt.Errorf("certificate cache exceeds %d bytes", maxCertificateCacheSize)
	}
	if err := validateCertificateCacheTarget(path); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".certificate-")
	if err != nil {
		return fmt.Errorf("create cache temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set cache temporary file mode: %w", err)
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write certificate cache: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync certificate cache: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close certificate cache: %w", err)
	}
	if _, err := c.prepareDirectory(); err != nil {
		return err
	}
	if err := validateCertificateCacheTarget(path); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace certificate cache: %w", err)
	}
	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open certificate cache directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync certificate cache directory: %w", err)
	}
	return nil
}

type tlsCertificateMaterial struct {
	cert *tls.Certificate
	ca   []byte
	pool *x509.CertPool
}

func (c *certificateCache) prepareDirectory() (string, error) {
	if !filepath.IsAbs(c.dir) || filepath.Clean(c.dir) != c.dir {
		return "", errors.New("certificate cache directory must be an absolute clean path")
	}
	info, err := os.Lstat(c.dir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(c.dir, 0o700); err != nil {
			return "", fmt.Errorf("create certificate cache directory: %w", err)
		}
		if err := os.Chmod(c.dir, 0o700); err != nil {
			return "", fmt.Errorf("set certificate cache directory mode: %w", err)
		}
		info, err = os.Lstat(c.dir)
	}
	if err != nil {
		return "", fmt.Errorf("inspect certificate cache directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("certificate cache directory must be a nonsymlink directory")
	}
	if info.Mode().Perm() != 0o700 {
		return "", fmt.Errorf("certificate cache directory must have mode 0700, got %04o", info.Mode().Perm())
	}
	if err := validateCertificateCacheOwner(info); err != nil {
		return "", fmt.Errorf("certificate cache directory: %w", err)
	}
	canonical, err := filepath.EvalSymlinks(c.dir)
	if err != nil {
		return "", fmt.Errorf("canonicalize certificate cache directory: %w", err)
	}
	if !filepath.IsAbs(canonical) {
		return "", errors.New("canonical certificate cache directory is not absolute")
	}
	if canonical != c.dir {
		return "", fmt.Errorf("certificate cache directory must be canonical, resolved to %q", canonical)
	}
	return canonical, nil
}

func validateCertificateCacheTarget(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect cache target: %w", err)
	}
	return validateCertificateCacheFile(info)
}

func validateCertificateCacheFile(info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("certificate cache file must be a nonsymlink regular file")
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("certificate cache file must have mode 0600, got %04o", info.Mode().Perm())
	}
	if err := validateCertificateCacheOwner(info); err != nil {
		return fmt.Errorf("certificate cache file: %w", err)
	}
	return nil
}

func decodeCertificateCache(data []byte) (*certificateCacheEnvelope, error) {
	var fields map[string]json.RawMessage
	if err := decodeStrictJSON(data, &fields); err != nil {
		return nil, fmt.Errorf("decode certificate cache: %w", err)
	}
	for _, field := range []string{"version", "hostnames", "ips", "certificate"} {
		if _, ok := fields[field]; !ok {
			return nil, fmt.Errorf("certificate cache is missing %q", field)
		}
	}
	if len(fields) != 4 {
		return nil, errors.New("certificate cache contains unknown fields")
	}
	var envelope certificateCacheEnvelope
	if err := decodeStrictJSON(data, &envelope); err != nil {
		return nil, fmt.Errorf("decode certificate cache: %w", err)
	}
	if envelope.Version != certificateCacheVersion {
		return nil, fmt.Errorf("certificate cache has unsupported version %d", envelope.Version)
	}
	hosts, ips, err := canonicalCertificateIdentities(envelope.Hostnames, envelope.IPs)
	if err != nil {
		return nil, fmt.Errorf("certificate cache identities: %w", err)
	}
	if !equalStrings(envelope.Hostnames, hosts) || !equalStrings(envelope.IPs, ips) {
		return nil, errors.New("certificate cache identities are not canonical sorted lists")
	}
	return &envelope, nil
}

func decodeStrictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
