package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blindport/blindport/internal/tcpproxy"
	"github.com/blindport/blindport/internal/tunnel"
)

func TestIperf3ThroughMultiplexedTunnel(t *testing.T) {
	iperf3, err := exec.LookPath("iperf3")
	if err != nil {
		t.Skip("iperf3 is unavailable")
	}

	originPort := reserveTCPPort(t)
	origin := exec.Command(iperf3, "-s", "-p", strconv.Itoa(originPort))
	var originOutput bytes.Buffer
	origin.Stdout = &originOutput
	origin.Stderr = &originOutput
	if err := origin.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = origin.Process.Kill()
		_ = origin.Wait()
	})
	waitForTCPListener(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(originPort)))

	public, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer public.Close()

	agentRaw, relayRaw := net.Pipe()
	var agentActive atomic.Int64
	agent := tunnel.New(agentRaw, func(stream *tunnel.Stream) {
		agentActive.Add(1)
		defer agentActive.Add(-1)
		handleTCPStream(slog.Default(), stream, net.JoinHostPort("127.0.0.1", strconv.Itoa(originPort)))
	})
	relay := tunnel.New(relayRaw, nil)
	agent.EnableTCPHalfClose()
	relay.EnableTCPHalfClose()
	agentRun := make(chan error, 1)
	relayRun := make(chan error, 1)
	go func() { agentRun <- agent.Run() }()
	go func() { relayRun <- relay.Run() }()
	defer agent.Close()
	defer relay.Close()

	var relayActive atomic.Int64
	var opened atomic.Int64
	var proxies sync.WaitGroup
	acceptDone := make(chan error, 1)
	go func() {
		for {
			conn, err := public.Accept()
			if err != nil {
				acceptDone <- err
				return
			}
			stream, err := relay.OpenStream("tcp", conn.RemoteAddr().String(), conn.LocalAddr().String())
			if err != nil {
				_ = conn.Close()
				acceptDone <- err
				return
			}
			opened.Add(1)
			relayActive.Add(1)
			proxies.Add(1)
			go func() {
				defer proxies.Done()
				defer relayActive.Add(-1)
				tcpproxy.Proxy(conn, stream)
			}()
		}
	}()

	for _, reverse := range []bool{false, true} {
		mode := "forward"
		args := []string{"-c", "127.0.0.1", "-p", strconv.Itoa(public.Addr().(*net.TCPAddr).Port), "-t", "1", "-J"}
		if reverse {
			mode = "reverse"
			args = append(args, "-R")
		}
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, iperf3, args...).CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("iperf3 timed out: %s", output)
			}
			if err != nil {
				t.Fatalf("iperf3 failed: %v\n%s", err, output)
			}
		})
	}

	if opened.Load() < 4 {
		t.Fatalf("opened %d streams, want separate control and data streams in both modes", opened.Load())
	}
	waitForNoActiveProxies(t, relay, agent, &relayActive, &agentActive)
	_ = public.Close()
	if err := <-acceptDone; err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	proxies.Wait()

	_ = relay.Close()
	_ = agent.Close()
	for name, runDone := range map[string]<-chan error{"relay": relayRun, "agent": agentRun} {
		select {
		case err := <-runDone:
			if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("%s tunnel: %v", name, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s tunnel did not stop", name)
		}
	}
}

func reserveTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func waitForTCPListener(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 25*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("iperf3 server did not listen on %s", address)
}

func waitForNoActiveProxies(t *testing.T, relay, agent *tunnel.Conn, relayActive, agentActive *atomic.Int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if relayActive.Load() == 0 && agentActive.Load() == 0 && relay.ActiveStreamCount() == 0 && agent.ActiveStreamCount() == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf(
		"active streams after iperf3: relay proxies=%d tunnel=%d, agent proxies=%d tunnel=%d",
		relayActive.Load(), relay.ActiveStreamCount(), agentActive.Load(), agent.ActiveStreamCount(),
	)
}
