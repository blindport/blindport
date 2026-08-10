package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const userServiceName = "blindportd.service"

type userServiceOptions struct {
	configPath      string
	tokenPath       string
	stateDir        string
	backendURL      string
	relayOverride   string
	serverName      string
	socks5Address   string
	acmeEmail       string
	acmeDirectory   string
	insecureSkipTLS bool
	wireguard       bool
	docker          bool
	input           *os.File
	output          io.Writer
	executable      string
	systemctl       string
}

func installUserService(options userServiceOptions) error {
	if options.wireguard {
		return errors.New("user service installation is unavailable in WireGuard mode")
	}
	if options.docker {
		return errors.New("user service installation is unavailable in Docker mode")
	}
	if options.output == nil {
		options.output = io.Discard
	}

	defaultConfigPath := defaultStaticConfigFile()
	if options.configPath != "" && options.configPath != defaultConfigPath {
		return fmt.Errorf("user service installation uses the default static config path %s; unset BLINDPORT_CONFIG and place the config there", defaultConfigPath)
	}
	configPath := defaultConfigPath
	configPath, err := canonicalAbsolutePath(configPath, "static config")
	if err != nil {
		return err
	}
	config, err := loadOwnerOnlyStaticConfigDocument(configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("static config not found at %s; create an owner-only versioned config first", configPath)
		}
		return fmt.Errorf("validate static config: %w", err)
	}

	tokenPath, stateDir := "", ""
	if config.IsMultiAccount() {
		if err := prepareUserServiceAccounts(config.Accounts, options.input, options.output); err != nil {
			return err
		}
	} else {
		tokenPath, err = canonicalAbsolutePath(options.tokenPath, "token file")
		if err != nil {
			return err
		}
		stateDir, err = canonicalAbsolutePath(options.stateDir, "state directory")
		if err != nil {
			return err
		}
		if err := ensureServiceToken(tokenPath, options.input, options.output); err != nil {
			return err
		}
		if err := prepareCredentialStateDir(stateDir); err != nil {
			return fmt.Errorf("validate identity state directory: %w", err)
		}
	}

	executable := options.executable
	if executable == "" {
		executable, err = os.Executable()
		if err != nil {
			return fmt.Errorf("locate blindportd executable: %w", err)
		}
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return fmt.Errorf("resolve blindportd executable: %w", err)
	}
	if resolved, resolveErr := filepath.EvalSymlinks(executable); resolveErr == nil {
		executable = resolved
	}
	if err := validateServiceExecutable(executable); err != nil {
		return err
	}

	systemctl := options.systemctl
	if systemctl == "" {
		systemctl, err = exec.LookPath("systemctl")
		if err != nil {
			return errors.New("systemd is unavailable: systemctl was not found in PATH")
		}
	}
	if err := runUserSystemctl(systemctl, "show-environment"); err != nil {
		return fmt.Errorf("user systemd is unavailable: %w", err)
	}

	unitDir, err := userSystemdDirectory()
	if err != nil {
		return err
	}
	if err := prepareOwnerControlledDirectory(unitDir); err != nil {
		return fmt.Errorf("prepare user systemd directory: %w", err)
	}
	unitPath := filepath.Join(unitDir, userServiceName)
	runtimeArguments := make([]string, 0, 7)
	for _, argument := range []string{
		flagArgument("backend", options.backendURL),
		flagArgument("relay", options.relayOverride),
		flagArgument("server-name", options.serverName),
		flagArgument("socks5", options.socks5Address),
		flagArgument("acme-email", options.acmeEmail),
		flagArgument("acme-directory", options.acmeDirectory),
	} {
		if argument != "" {
			runtimeArguments = append(runtimeArguments, argument)
		}
	}
	if options.insecureSkipTLS {
		runtimeArguments = append(runtimeArguments, "-insecure-skip-tls")
	}
	unit, err := renderUserService(executable, configPath, tokenPath, stateDir, runtimeArguments...)
	if err != nil {
		return err
	}
	if err := writeOwnerOnlyAtomic(unitPath, []byte(unit)); err != nil {
		return fmt.Errorf("write user unit: %w", err)
	}
	if err := runUserSystemctl(systemctl, "daemon-reload"); err != nil {
		return err
	}
	if err := runUserSystemctl(systemctl, "enable", "--now", userServiceName); err != nil {
		return err
	}

	fmt.Fprintf(options.output, "Installed and started %s\n", unitPath)
	fmt.Fprintf(options.output, "Status: systemctl --user status %s\n", userServiceName)
	fmt.Fprintf(options.output, "Logs: journalctl --user -u %s -f\n", userServiceName)
	fmt.Fprintln(options.output, `Start at boot without logging in: loginctl enable-linger "$USER" (administrator approval may be required)`)
	return nil
}

func ensureServiceToken(path string, input *os.File, output io.Writer) error {
	token, err := loadTokenFile(path)
	if err != nil {
		return fmt.Errorf("validate token file: %w", err)
	}
	if token != "" {
		return nil
	}
	token, err = promptAndStoreToken(path, input, output)
	if err != nil {
		return fmt.Errorf("store token: %w", err)
	}
	if token == "" {
		return fmt.Errorf("token file not found at %s; rerun -install-user-service from an interactive terminal", path)
	}
	return nil
}

func prepareUserServiceAccounts(accounts []staticAccount, input *os.File, output io.Writer) error {
	for _, account := range accounts {
		tokenPath, err := canonicalAbsolutePath(account.TokenFile, "account token file")
		if err != nil {
			return fmt.Errorf("prepare account %q: %w", account.Name, err)
		}
		if err := ensureServiceAccountToken(tokenPath, input, output); err != nil {
			return fmt.Errorf("prepare account %q token: %w", account.Name, err)
		}
		stateDir, err := canonicalAbsolutePath(account.StateDir, "account state directory")
		if err != nil {
			return fmt.Errorf("prepare account %q: %w", account.Name, err)
		}
		if err := prepareCredentialStateDir(stateDir); err != nil {
			return fmt.Errorf("prepare account %q state directory: %w", account.Name, err)
		}
	}
	return nil
}

func ensureServiceAccountToken(path string, input *os.File, output io.Writer) error {
	if _, err := loadStaticAccountToken(path); err == nil {
		return nil
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("account token file is invalid or unsafe")
	}
	token, err := promptAndStoreToken(path, input, output)
	if err != nil {
		return fmt.Errorf("store account token: %w", err)
	}
	if token == "" {
		return fmt.Errorf("token file not found at %s; rerun -install-user-service from an interactive terminal", path)
	}
	if _, err := loadStaticAccountToken(path); err != nil {
		return errors.New("stored account token file is invalid or unsafe")
	}
	return nil
}

func canonicalAbsolutePath(path, name string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("%s path is unavailable", name)
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve %s path: %w", name, err)
	}
	if filepath.Clean(path) != absPath {
		return "", fmt.Errorf("%s path must be absolute and canonical", name)
	}
	return absPath, nil
}

func validateServiceExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspect blindportd executable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New("blindportd executable must be a regular executable file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("blindportd executable must not be writable by group or others")
	}
	if err := validateServiceExecutableOwner(info); err != nil {
		return err
	}
	return nil
}

func userSystemdDirectory() (string, error) {
	configHome, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate user config directory: %w", err)
	}
	return canonicalAbsolutePath(filepath.Join(configHome, "systemd", "user"), "user systemd directory")
}

func prepareOwnerControlledDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	if resolved != path {
		return errors.New("directory path must not contain symbolic links")
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return errors.New("directory must not be writable by group or others")
	}
	if err := validateStaticConfigOwner(info); err != nil {
		return err
	}
	return nil
}

func flagArgument(name, value string) string {
	if value == "" {
		return ""
	}
	return "-" + name + "=" + value
}

func renderUserService(executable, configPath, tokenPath, stateDir string, runtimeArguments ...string) (string, error) {
	arguments := []string{executable, "-config=" + configPath}
	if tokenPath != "" {
		arguments = append(arguments, "-token-file="+tokenPath)
	}
	if stateDir != "" {
		arguments = append(arguments, "-state-dir="+stateDir)
	}
	arguments = append(arguments, runtimeArguments...)
	quoted := make([]string, len(arguments))
	for i, argument := range arguments {
		value, err := quoteSystemdArgument(argument)
		if err != nil {
			return "", err
		}
		quoted[i] = value
	}
	return "[Unit]\nDescription=Blindport agent\nAfter=network-online.target\nWants=network-online.target\n\n" +
		"[Service]\nType=simple\nUMask=0077\nExecStart=" + strings.Join(quoted, " ") + "\n" +
		"Restart=on-failure\nRestartSec=5s\nNoNewPrivileges=true\nPrivateTmp=true\n\n" +
		"[Install]\nWantedBy=default.target\n", nil
}

func quoteSystemdArgument(value string) (string, error) {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return "", errors.New("systemd unit paths must not contain control characters")
		}
	}
	value = strings.ReplaceAll(value, "%", "%%")
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + value + `"`, nil
}

func writeOwnerOnlyAtomic(path string, data []byte) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("existing unit must be a regular file, not a symbolic link")
		}
		if info.Mode().Perm()&0o077 != 0 {
			return errors.New("existing unit must be owner-only")
		}
		if err := validateStaticConfigOwner(info); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".blindportd-service-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	remove := true
	defer func() {
		_ = temporary.Close()
		if remove {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	remove = false
	directoryFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryFile.Close()
	return directoryFile.Sync()
}

func runUserSystemctl(systemctl string, arguments ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, systemctl, append([]string{"--user"}, arguments...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return fmt.Errorf("systemctl --user %s failed: %s", strings.Join(arguments, " "), message)
	}
	return nil
}
