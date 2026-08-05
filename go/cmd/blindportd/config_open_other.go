//go:build !linux

package main

import "os"

func openStaticConfig(path string) (*os.File, error) {
	return os.Open(path)
}

func validateStaticConfigOwner(_ os.FileInfo) error {
	return nil
}

func validateServiceExecutableOwner(_ os.FileInfo) error {
	return nil
}
