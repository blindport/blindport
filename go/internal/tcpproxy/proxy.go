// Package tcpproxy copies bidirectional TCP byte streams with FIN propagation.
package tcpproxy

import (
	"io"
	"sync"
)

// Result contains byte counts and terminal copy errors relative to the arguments
// passed to Proxy.
type Result struct {
	LeftToRight    int64
	RightToLeft    int64
	LeftToRightErr error
	RightToLeftErr error
}

type closeWriter interface {
	CloseWrite() error
}

// Proxy copies both directions, propagates each clean EOF with CloseWrite, and
// owns both endpoints until both directions finish. A copy or CloseWrite error
// fully closes both endpoints to unblock the opposite direction.
func Proxy(left, right io.ReadWriteCloser) Result {
	return ProxyObserved(left, right, nil, nil)
}

// ProxyObserved preserves Proxy's lifecycle semantics while observing every
// successful destination write. Callbacks receive partial writes immediately.
func ProxyObserved(left, right io.ReadWriteCloser, leftToRight, rightToLeft func(int)) Result {
	type copyResult struct {
		leftToRight bool
		bytes       int64
		err         error
	}
	done := make(chan copyResult, 2)
	var closeOnce sync.Once
	var closeWait sync.WaitGroup
	closeEndpoints := func() {
		closeOnce.Do(func() {
			closeWait.Add(2)
			go func() {
				defer closeWait.Done()
				_ = left.Close()
			}()
			go func() {
				defer closeWait.Done()
				_ = right.Close()
			}()
		})
	}
	copyDirection := func(dst io.ReadWriteCloser, src io.Reader, isLeftToRight bool, observed func(int)) {
		if observed != nil {
			dst = observedWriter{ReadWriteCloser: dst, observe: observed}
		}
		copied, err := io.Copy(dst, src)
		if err == nil {
			if half, ok := dst.(closeWriter); ok {
				err = half.CloseWrite()
			} else {
				err = dst.Close()
			}
		}
		if err != nil {
			closeEndpoints()
		}
		done <- copyResult{leftToRight: isLeftToRight, bytes: copied, err: err}
	}
	go copyDirection(right, left, true, leftToRight)
	go copyDirection(left, right, false, rightToLeft)

	var result Result
	for range 2 {
		copied := <-done
		if copied.leftToRight {
			result.LeftToRight = copied.bytes
			result.LeftToRightErr = copied.err
		} else {
			result.RightToLeft = copied.bytes
			result.RightToLeftErr = copied.err
		}
	}
	closeEndpoints()
	closeWait.Wait()
	return result
}

type observedWriter struct {
	io.ReadWriteCloser
	observe func(int)
}

// CloseWrite must remain visible after wrapping or ProxyObserved would turn a
// negotiated TCP FIN into a full close.
func (w observedWriter) CloseWrite() error {
	if half, ok := w.ReadWriteCloser.(closeWriter); ok {
		return half.CloseWrite()
	}
	return w.ReadWriteCloser.Close()
}

func (w observedWriter) Write(payload []byte) (int, error) {
	n, err := w.ReadWriteCloser.Write(payload)
	if n > 0 {
		w.observe(n)
	}
	return n, err
}
