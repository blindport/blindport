// Package tcpproxy copies bidirectional TCP byte streams with FIN propagation.
package tcpproxy

import "io"

// Result contains byte counts relative to the arguments passed to Proxy.
type Result struct {
	LeftToRight int64
	RightToLeft int64
}

type closeWriter interface {
	CloseWrite() error
}

// Proxy copies both directions, propagates each EOF with CloseWrite, and owns
// both endpoints until both directions finish.
func Proxy(left, right io.ReadWriteCloser) Result {
	defer left.Close()
	defer right.Close()

	type copyResult struct {
		leftToRight bool
		bytes       int64
	}
	done := make(chan copyResult, 2)
	copyDirection := func(dst io.ReadWriteCloser, src io.Reader, leftToRight bool) {
		copied, _ := io.Copy(dst, src)
		if half, ok := dst.(closeWriter); ok {
			_ = half.CloseWrite()
		} else {
			_ = dst.Close()
		}
		done <- copyResult{leftToRight: leftToRight, bytes: copied}
	}
	go copyDirection(right, left, true)
	go copyDirection(left, right, false)

	var result Result
	for range 2 {
		copied := <-done
		if copied.leftToRight {
			result.LeftToRight = copied.bytes
		} else {
			result.RightToLeft = copied.bytes
		}
	}
	return result
}
