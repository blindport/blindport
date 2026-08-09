//go:build linux

package main

import (
	"errors"
	"os"
	"syscall"
)

func validateAccountTokenOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot determine token owner")
	}
	if stat.Uid == uint32(os.Geteuid()) || stat.Uid == 0 {
		return nil
	}
	return errors.New("token owner is not permitted")
}
