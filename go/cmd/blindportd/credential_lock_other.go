//go:build !linux

package main

import (
	"errors"
	"os"
)

func acquireCredentialLock(string) (*os.File, error) {
	return nil, errors.New("persistent credential locking is supported only on Linux")
}

func releaseCredentialLock(*os.File) error { return nil }
