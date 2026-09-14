//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func openStaticConfig(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("must not be a symbolic link: %w", err)
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func validateStaticConfigOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot determine file owner")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("owner UID %d does not match effective UID %d", stat.Uid, os.Geteuid())
	}
	return nil
}

func validateServiceExecutableOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot determine executable owner")
	}
	if stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("executable owner UID %d is neither root nor effective UID %d", stat.Uid, os.Geteuid())
	}
	return nil
}
