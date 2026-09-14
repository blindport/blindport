package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os/exec"
	"strconv"
	"strings"
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

	public, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer public.Close()

	agentRaw, relayRaw := net.Pipe()
	var agentActive atomic.Int64
	var originAddress atomic.Value
	originAddress.Store("")
	agent := tunnel.New(agentRaw, func(stream *tunnel.Stream) {
		agentActive.Add(1)
		defer agentActive.Add(-1)
		handleTCPStream(slog.Default(), stream, originAddress.Load().(string))
	})
	relay := tunnel.New(relayRaw, nil)
	agent.EnableTCPHalfClose()
	relay.EnableTCPHalfClose()
	agent.EnableStreamFlowControl()
	relay.EnableStreamFlowControl()
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
		if reverse {
			mode = "reverse"
		}
		t.Run(mode, func(t *testing.T) {
			originPort := reserveTCPPort(t)
			originAddress.Store(net.JoinHostPort("127.0.0.1", strconv.Itoa(originPort)))
			origin := startIperfServer(t, iperf3, originPort)
			defer func() { _, _ = origin.stop() }()

			args := []string{"-c", "127.0.0.1", "-p", strconv.Itoa(public.Addr().(*net.TCPAddr).Port), "-t", "1", "-J"}
			if reverse {
				args = append(args, "-R")
			}
			clientErr := runIperfClientWithStartupRetries(t, iperf3, args, relay, agent, &opened, &relayActive, &agentActive)
			waitForNoActiveProxies(t, relay, agent, &relayActive, &agentActive)
			originOutput, originErr := origin.stop()
			if clientErr != nil {
				t.Fatalf("%v\norigin output:\n%s", clientErr, originOutput)
			}
			if originErr != nil {
				t.Fatalf("stop iperf3 server: %v\n%s", originErr, originOutput)
			}
		})
	}

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

type iperfServer struct {
	cancel   context.CancelFunc
	command  *exec.Cmd
	output   bytes.Buffer
	stopOnce sync.Once
	stopErr  error
}

func startIperfServer(t *testing.T, executable string, port int) *iperfServer {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	server := &iperfServer{cancel: cancel}
	command := exec.CommandContext(ctx, executable, "-s", "-p", strconv.Itoa(port))
	command.WaitDelay = 2 * time.Second
	command.Stdout = &server.output
	command.Stderr = &server.output
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	server.command = command
	return server
}

func (s *iperfServer) stop() (string, error) {
	s.stopOnce.Do(func() {
		s.cancel()
		s.stopErr = s.command.Wait()
		if exitErr := (*exec.ExitError)(nil); errors.As(s.stopErr, &exitErr) && !exitErr.ProcessState.Exited() {
			s.stopErr = nil
		}
	})
	return s.output.String(), s.stopErr
}

func runIperfClientWithStartupRetries(
	t *testing.T,
	executable string,
	args []string,
	relay, agent *tunnel.Conn,
	opened, relayActive, agentActive *atomic.Int64,
) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var failures []string
	for attempt := 1; attempt <= 8; attempt++ {
		openedBefore := opened.Load()
		output, err := exec.CommandContext(ctx, executable, args...).CombinedOutput()
		waitForNoActiveProxies(t, relay, agent, relayActive, agentActive)
		openedByAttempt := opened.Load() - openedBefore
		if err == nil {
			if openedByAttempt < 2 {
				return fmt.Errorf("iperf3 opened %d streams, want separate control and data streams", openedByAttempt)
			}
			return nil
		}
		failures = append(failures, fmt.Sprintf("attempt %d (%d streams): %v\n%s", attempt, openedByAttempt, err, output))
		if ctx.Err() != nil || openedByAttempt >= 2 {
			break
		}
		timer := time.NewTimer(time.Duration(attempt*25) * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
		}
	}
	return fmt.Errorf("iperf3 did not complete after bounded startup retries:\n%s", strings.Join(failures, "\n"))
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
