package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validServiceConfig = `{"version":1,"mappings":[{"subscription_id":"11111111-1111-4111-8111-111111111111","upstream":"127.0.0.1:8080"}]}`

func TestInstallUserServiceWithFakeSystemctlAndHome(t *testing.T) {
	home, configHome, tokenPath, configPath, executable, systemctl, logPath := prepareUserServiceTest(t)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", configHome)

	var output strings.Builder
	options := userServiceOptions{
		tokenPath: tokenPath, stateDir: filepath.Join(home, ".local", "state", "blindport"),
		backendURL: "https://control.example", relayOverride: "relay.example:5443",
		serverName: "mtls.example", socks5Address: "127.0.0.1:9050",
		acmeEmail: "owner@example.com", acmeDirectory: "https://acme.example/directory",
		insecureSkipTLS: true, input: nil, output: &output,
		executable: executable, systemctl: systemctl,
	}
	if err := installUserService(options); err != nil {
		t.Fatal(err)
	}
	if err := installUserService(options); err != nil {
		t.Fatalf("idempotent install: %v", err)
	}

	unitPath := filepath.Join(configHome, "systemd", "user", userServiceName)
	unit, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("unit mode = %04o", info.Mode().Perm())
	}
	text := string(unit)
	for _, expected := range []string{
		`ExecStart="` + strings.ReplaceAll(executable, "%", "%%") + `"`,
		`"-config=` + configPath + `"`,
		`"-token-file=` + tokenPath + `"`,
		`"-state-dir=` + filepath.Join(home, ".local", "state", "blindport") + `"`,
		`"-backend=https://control.example"`,
		`"-relay=relay.example:5443"`,
		`"-server-name=mtls.example"`,
		`"-socks5=127.0.0.1:9050"`,
		`"-acme-email=owner@example.com"`,
		`"-acme-directory=https://acme.example/directory"`,
		`"-insecure-skip-tls"`,
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("unit missing %q:\n%s", expected, text)
		}
	}
	if strings.Contains(text, "PRIVATE-TOKEN") {
		t.Fatal("unit contains bearer token")
	}
	commands, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	wantCommands := "--user show-environment\n--user daemon-reload\n--user enable --now blindportd.service\n" +
		"--user show-environment\n--user daemon-reload\n--user enable --now blindportd.service\n"
	if string(commands) != wantCommands {
		t.Fatalf("systemctl commands:\n%s", commands)
	}
	if !strings.Contains(output.String(), "systemctl --user status blindportd.service") ||
		!strings.Contains(output.String(), "journalctl --user -u blindportd.service -f") ||
		!strings.Contains(output.String(), `loginctl enable-linger "$USER"`) {
		t.Fatalf("installer output:\n%s", output.String())
	}
}

func TestInstallUserServiceRejectsUnsupportedModes(t *testing.T) {
	for _, test := range []struct {
		name    string
		options userServiceOptions
		want    string
	}{
		{name: "WireGuard", options: userServiceOptions{wireguard: true}, want: "WireGuard mode"},
		{name: "Docker", options: userServiceOptions{docker: true}, want: "Docker mode"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := installUserService(test.options); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestInstallUserServiceRequiresConfigAndSystemd(t *testing.T) {
	home, configHome, tokenPath, configPath, executable, _, _ := prepareUserServiceTest(t)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", configHome)
	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	options := userServiceOptions{
		tokenPath:  tokenPath,
		stateDir:   filepath.Join(home, ".local", "state", "blindport"),
		executable: executable,
		output:     io.Discard,
	}
	if err := installUserService(options); err == nil || !strings.Contains(err.Error(), "static config not found") {
		t.Fatalf("missing config error = %v", err)
	}
	writeTestFile(t, configPath, validServiceConfig, 0o600)
	t.Setenv("PATH", t.TempDir())
	if err := installUserService(options); err == nil || !strings.Contains(err.Error(), "systemctl was not found") {
		t.Fatalf("missing systemd error = %v", err)
	}
}

func TestInstallUserServiceRejectsUnavailableUserSystemd(t *testing.T) {
	home, configHome, tokenPath, _, executable, systemctl, _ := prepareUserServiceTest(t)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", configHome)
	writeTestFile(t, systemctl, "#!/bin/sh\nprintf 'Failed to connect to bus\\n' >&2\nexit 1\n", 0o700)
	err := installUserService(userServiceOptions{
		tokenPath:  tokenPath,
		stateDir:   filepath.Join(home, ".local", "state", "blindport"),
		executable: executable,
		systemctl:  systemctl,
		output:     io.Discard,
	})
	if err == nil || !strings.Contains(err.Error(), "user systemd is unavailable") || !strings.Contains(err.Error(), "Failed to connect to bus") {
		t.Fatalf("unavailable user systemd error = %v", err)
	}
}

func TestInstallUserServiceRejectsNonDefaultConfig(t *testing.T) {
	home, configHome, tokenPath, _, executable, systemctl, _ := prepareUserServiceTest(t)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", configHome)
	err := installUserService(userServiceOptions{
		configPath: filepath.Join(home, "other.json"),
		tokenPath:  tokenPath,
		stateDir:   filepath.Join(home, ".local", "state", "blindport"),
		executable: executable,
		systemctl:  systemctl,
		output:     io.Discard,
	})
	if err == nil || !strings.Contains(err.Error(), "default static config path") {
		t.Fatalf("nondefault config error = %v", err)
	}
}

func TestInstallUserServiceRejectsUnsafeFiles(t *testing.T) {
	home, configHome, tokenPath, configPath, executable, systemctl, _ := prepareUserServiceTest(t)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", configHome)
	options := userServiceOptions{
		tokenPath:  tokenPath,
		stateDir:   filepath.Join(home, ".local", "state", "blindport"),
		executable: executable,
		systemctl:  systemctl,
		output:     io.Discard,
	}

	if err := os.Chmod(configPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := installUserService(options); err == nil || !strings.Contains(err.Error(), "owner-only") {
		t.Fatalf("unsafe config error = %v", err)
	}
	if err := os.Chmod(configPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tokenPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := installUserService(options); err == nil || !strings.Contains(err.Error(), "expose the bearer token") {
		t.Fatalf("unsafe token error = %v", err)
	}
}

func TestInstallUserServiceRejectsUnsafeIdentityState(t *testing.T) {
	home, configHome, tokenPath, _, executable, systemctl, _ := prepareUserServiceTest(t)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", configHome)
	stateDir := filepath.Join(home, ".local", "state", "blindport")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	err := installUserService(userServiceOptions{
		tokenPath:  tokenPath,
		stateDir:   stateDir,
		executable: executable,
		systemctl:  systemctl,
		output:     io.Discard,
	})
	if err == nil || !strings.Contains(err.Error(), "expose private state") {
		t.Fatalf("unsafe identity state error = %v", err)
	}
}

func TestInstallUserServiceRejectsUnsafeExistingUnit(t *testing.T) {
	home, configHome, tokenPath, _, executable, systemctl, _ := prepareUserServiceTest(t)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", configHome)
	unitDir := filepath.Join(configHome, "systemd", "user")
	if err := os.MkdirAll(unitDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(unitDir, userServiceName), "unsafe", 0o644)
	err := installUserService(userServiceOptions{
		tokenPath:  tokenPath,
		stateDir:   filepath.Join(home, ".local", "state", "blindport"),
		executable: executable,
		systemctl:  systemctl,
		output:     io.Discard,
	})
	if err == nil || !strings.Contains(err.Error(), "existing unit must be owner-only") {
		t.Fatalf("unsafe unit error = %v", err)
	}
}

func TestRenderUserServiceRejectsControlCharacters(t *testing.T) {
	if _, err := renderUserService("/tmp/blindportd\nExecStart=/bin/false", "/config", "/token", "/state"); err == nil {
		t.Fatal("render accepted a unit directive injection")
	}
}

func prepareUserServiceTest(t *testing.T) (string, string, string, string, string, string, string) {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	configHome := filepath.Join(home, "config home")
	tokenPath := filepath.Join(configHome, "blindport", "token")
	configPath := filepath.Join(configHome, "blindport", "config.json")
	executable := filepath.Join(home, "bin", "blindportd%test")
	systemctl := filepath.Join(root, "fake-systemctl")
	logPath := filepath.Join(root, "systemctl.log")
	for _, directory := range []string{home, filepath.Dir(tokenPath), filepath.Dir(executable)} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := storeToken(tokenPath, "PRIVATE-TOKEN"); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, configPath, validServiceConfig, 0o600)
	writeTestFile(t, executable, "binary", 0o700)
	writeTestFile(t, systemctl, "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$SYSTEMCTL_LOG\"\n", 0o700)
	t.Setenv("SYSTEMCTL_LOG", logPath)
	return home, configHome, tokenPath, configPath, executable, systemctl, logPath
}

func writeTestFile(t *testing.T, path, contents string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
}
