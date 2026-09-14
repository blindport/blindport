//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestLoadStaticConfigRejectsWrongOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		if _, err := loadStaticConfig("/etc/passwd"); err == nil || !strings.Contains(err.Error(), "does not match effective UID") {
			t.Fatalf("loadStaticConfig() error = %v", err)
		}
		return
	}
	path := writeConfig(t, `{"version":1,"mappings":[{"subscription_id":"11111111-1111-4111-8111-111111111111","upstream":"app:80"}]}`, 0o600)
	if err := os.Chown(path, 1, -1); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStaticConfig(path); err == nil || !strings.Contains(err.Error(), "does not match effective UID") {
		t.Fatalf("loadStaticConfig() error = %v", err)
	}
}

func TestLoadStaticConfigRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStaticConfig(path); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("loadStaticConfig() error = %v", err)
	}
}
