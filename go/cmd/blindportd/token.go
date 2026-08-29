package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"
)

const legacyTokenFile = "/etc/blindport/token"

func defaultTokenFile() string {
	if configured := os.Getenv("BLINDPORT_TOKEN_FILE"); configured != "" {
		return configured
	}
	if configHome := os.Getenv("XDG_CONFIG_HOME"); configHome != "" {
		return filepath.Join(configHome, "blindport", "token")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return legacyTokenFile
	}
	return filepath.Join(home, ".config", "blindport", "token")
}

func defaultStaticConfigFile() string {
	if configHome := os.Getenv("XDG_CONFIG_HOME"); configHome != "" {
		return filepath.Join(configHome, "blindport", "config.json")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".config", "blindport", "config.json")
}

func validateToken(token string) error {
	if token == "" {
		return errors.New("token is empty")
	}
	if strings.IndexFunc(token, func(r rune) bool {
		return r == 0 || r == '\n' || r == '\r' || r == '\t' || r == ' '
	}) >= 0 {
		return errors.New("token must contain exactly one value without whitespace")
	}
	if len(token) > 8192 {
		return errors.New("token exceeds 8192 bytes")
	}
	return nil
}

func loadStaticAccountToken(path string) (string, error) {
	token, _, err := loadStaticAccountTokenWithWarnings(path)
	return token, err
}

func loadStaticAccountTokenWithWarnings(path string) (string, []error, error) {
	if err := validateStaticConfigPath(path, "token_file"); err != nil {
		return "", nil, fmt.Errorf("invalid account token file %q: %w", path, err)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return "", nil, accountTokenFileAccessError("inspect", path, err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 {
		return "", nil, fmt.Errorf("account token file %q must not be a symbolic link", path)
	}
	file, err := openStaticConfig(path)
	if err != nil {
		return "", nil, accountTokenFileAccessError("open", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", nil, fmt.Errorf("inspect opened account token file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return "", nil, fmt.Errorf("account token file %q must be a regular file", path)
	}
	warnings := make([]error, 0, 2)
	if info.Mode().Perm()&0o077 != 0 {
		warnings = append(warnings, fmt.Errorf("mode %04o allows access by group or others", info.Mode().Perm()))
	}
	if err := validateAccountTokenOwner(info); err != nil {
		warnings = append(warnings, err)
	}
	data, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil {
		return "", nil, fmt.Errorf("read account token file %q: %w", path, err)
	}
	if len(data) > 8192 {
		return "", nil, fmt.Errorf("account token file %q exceeds 8192 bytes", path)
	}
	token := strings.TrimSpace(string(data))
	if err := validateToken(token); err != nil {
		return "", nil, fmt.Errorf("invalid token in account token file %q: %w", path, err)
	}
	return token, warnings, nil
}

func accountTokenFileAccessError(operation, path string, err error) error {
	if errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("%s account token file %q: %w (running as UID %d GID %d; ensure every parent directory is traversable, normally mode 0700)", operation, path, err, os.Geteuid(), os.Getegid())
	}
	return fmt.Errorf("%s account token file %q: %w", operation, path, err)
}

func promptAndStoreToken(path string, input *os.File, output io.Writer) (string, error) {
	if input == nil || !term.IsTerminal(int(input.Fd())) {
		return "", nil
	}
	if path == "" {
		return "", errors.New("token file path is required for interactive setup")
	}
	_, _ = fmt.Fprint(output, "Blindport account token: ")
	value, err := term.ReadPassword(int(input.Fd()))
	_, _ = fmt.Fprintln(output)
	if err != nil {
		return "", fmt.Errorf("read token: %w", err)
	}
	token := strings.TrimSpace(string(value))
	if err := validateToken(token); err != nil {
		return "", err
	}
	if err := storeToken(path, token); err != nil {
		return "", err
	}
	_, _ = fmt.Fprintf(output, "Token saved to %s\n", path)
	return token, nil
}

func storeToken(path, token string) error {
	if err := validateToken(token); err != nil {
		return err
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve token file: %w", err)
	}
	directory := filepath.Dir(absPath)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create token directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect token directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("token directory must be a directory, not a symbolic link")
	}
	if err := validateStaticConfigOwner(info); err != nil {
		return fmt.Errorf("token directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("protect token directory: %w", err)
	}

	file, err := os.OpenFile(absPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create token file: %w", err)
	}
	removeOnFailure := true
	defer func() {
		_ = file.Close()
		if removeOnFailure {
			_ = os.Remove(absPath)
		}
	}()
	if _, err := io.WriteString(file, token+"\n"); err != nil {
		return fmt.Errorf("write token file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync token file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close token file: %w", err)
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open token directory: %w", err)
	}
	if err := directoryFile.Sync(); err != nil {
		_ = directoryFile.Close()
		return fmt.Errorf("sync token directory: %w", err)
	}
	if err := directoryFile.Close(); err != nil {
		return fmt.Errorf("close token directory: %w", err)
	}
	removeOnFailure = false
	return nil
}
