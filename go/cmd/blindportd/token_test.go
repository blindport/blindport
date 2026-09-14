package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultTokenFileUsesEnvironmentThenXDG(t *testing.T) {
	t.Setenv("BLINDPORT_TOKEN_FILE", "/run/secrets/blindport-token")
	if got := defaultTokenFile(); got != "/run/secrets/blindport-token" {
		t.Fatalf("explicit token file = %q", got)
	}
	t.Setenv("BLINDPORT_TOKEN_FILE", "")
	t.Setenv("XDG_CONFIG_HOME", "/tmp/private-config")
	if got := defaultTokenFile(); got != "/tmp/private-config/blindport/token" {
		t.Fatalf("XDG token file = %q", got)
	}
}

func TestStoreTokenCreatesPrivateFileAndDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config", "blindport", "token")
	if err := storeToken(path, "PRIVATE-TOKEN"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "PRIVATE-TOKEN\n" {
		t.Fatalf("stored token = %q", data)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	directoryInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if fileInfo.Mode().Perm() != 0o600 || directoryInfo.Mode().Perm() != 0o700 {
		t.Fatalf("stored modes = file %04o, directory %04o", fileInfo.Mode().Perm(), directoryInfo.Mode().Perm())
	}
	if err := storeToken(path, "REPLACEMENT"); err == nil || !strings.Contains(err.Error(), "file exists") {
		t.Fatalf("replacement error = %v", err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "PRIVATE-TOKEN\n" {
		t.Fatal("existing token was replaced")
	}
}

func TestPromptDoesNotRunWithoutTerminal(t *testing.T) {
	input, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	path := filepath.Join(t.TempDir(), "token")
	token, err := promptAndStoreToken(path, input, io.Discard)
	if err != nil || token != "" {
		t.Fatalf("nonterminal prompt = %q, %v", token, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("nonterminal token file error = %v", err)
	}
}

func TestLoadTokenValidatesDirectSources(t *testing.T) {
	if _, err := loadToken("two tokens", "/missing"); err == nil || !strings.Contains(err.Error(), "token argument") {
		t.Fatalf("invalid token argument error = %v", err)
	}
	t.Setenv("BLINDPORT_TOKEN", "two tokens")
	if _, err := loadToken("", "/missing"); err == nil || !strings.Contains(err.Error(), "BLINDPORT_TOKEN") {
		t.Fatalf("invalid environment token error = %v", err)
	}
}

func TestStoreTokenRejectsWhitespaceAndSymlinkDirectory(t *testing.T) {
	if err := storeToken(filepath.Join(t.TempDir(), "token"), "two tokens"); err == nil {
		t.Fatal("token with whitespace was stored")
	}
	root := t.TempDir()
	realDirectory := filepath.Join(root, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked")
	if err := os.Symlink(realDirectory, link); err != nil {
		t.Fatal(err)
	}
	if err := storeToken(filepath.Join(link, "token"), "PRIVATE"); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symlink directory error = %v", err)
	}
}
