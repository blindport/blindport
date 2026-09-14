//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func acquireCredentialLock(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("credential lock must not be a symbolic link: %w", err)
		}
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, statErr := file.Stat()
	if statErr != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect credential lock: %w", statErr)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		return nil, errors.New("credential lock must be a private regular file")
	}
	if ownerErr := validateStaticConfigOwner(info); ownerErr != nil {
		_ = file.Close()
		return nil, fmt.Errorf("credential lock: %w", ownerErr)
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.New("credential state is already locked by another blindportd process")
		}
		return nil, fmt.Errorf("lock credential state: %w", err)
	}
	return file, nil
}

func releaseCredentialLock(file *os.File) error {
	if file == nil {
		return nil
	}
	err := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}
