//go:build !linux

package main

import "os"

func validateAccountTokenOwner(info os.FileInfo) error {
	return validateStaticConfigOwner(info)
}
