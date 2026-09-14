//go:build !linux

package main

import "os"

func openCertificateCacheFile(path string) (*os.File, error) {
	return os.Open(path)
}

func validateCertificateCacheOwner(_ os.FileInfo) error {
	return nil
}
