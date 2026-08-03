package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"sync"
	"time"
)

const stableSessionDuration = time.Minute

type tlsMaterial struct {
	certificate          tls.Certificate
	rootCAs              *x509.CertPool
	getClientCertificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
}

type workerKey struct {
	subscriptionID int64
	relayAddr      string
}

type supervisedWorker struct {
	plan   workerPlan
	cancel context.CancelFunc
	done   chan struct{}
}

type workerSupervisor struct {
	reconcileMu sync.Mutex
	mu          sync.Mutex
	ctx         context.Context
	cancel      context.CancelFunc
	run         func(context.Context, workerPlan)
	workers     map[workerKey]*supervisedWorker
}

func newWorkerSupervisor(ctx context.Context, run func(context.Context, workerPlan)) *workerSupervisor {
	supervisorCtx, cancel := context.WithCancel(ctx)
	return &workerSupervisor{
		ctx: supervisorCtx, cancel: cancel, run: run,
		workers: make(map[workerKey]*supervisedWorker),
	}
}

func (s *workerSupervisor) Reconcile(plans []workerPlan) error {
	desired := make(map[workerKey]workerPlan, len(plans))
	for _, plan := range plans {
		key := workerKey{subscriptionID: plan.SubscriptionID, relayAddr: plan.RelayAddr}
		if _, exists := desired[key]; exists {
			return fmt.Errorf("duplicate worker plan for subscription %d relay %s", plan.SubscriptionID, plan.RelayAddr)
		}
		desired[key] = plan
	}

	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	s.mu.Lock()
	stopping := make([]*supervisedWorker, 0)
	for key, worker := range s.workers {
		plan, keep := desired[key]
		if keep && sameWorkerPlan(worker.plan, plan) {
			delete(desired, key)
			continue
		}
		delete(s.workers, key)
		worker.cancel()
		stopping = append(stopping, worker)
	}
	s.mu.Unlock()
	for _, worker := range stopping {
		<-worker.done
	}
	if s.ctx.Err() != nil {
		return s.ctx.Err()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for key, plan := range desired {
		workerCtx, cancel := context.WithCancel(s.ctx)
		worker := &supervisedWorker{plan: plan, cancel: cancel, done: make(chan struct{})}
		s.workers[key] = worker
		go func(key workerKey, worker *supervisedWorker) {
			defer close(worker.done)
			defer func() {
				s.mu.Lock()
				if s.workers[key] == worker {
					delete(s.workers, key)
				}
				s.mu.Unlock()
			}()
			s.run(workerCtx, worker.plan)
		}(key, worker)
	}
	return nil
}

func (s *workerSupervisor) Shutdown() {
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	s.cancel()
	s.mu.Lock()
	workers := make([]*supervisedWorker, 0, len(s.workers))
	for key, worker := range s.workers {
		delete(s.workers, key)
		worker.cancel()
		workers = append(workers, worker)
	}
	s.mu.Unlock()
	for _, worker := range workers {
		<-worker.done
	}
}

func sameWorkerPlan(a, b workerPlan) bool {
	if a.SubscriptionID != b.SubscriptionID || a.RelayAddr != b.RelayAddr || a.Upstream != b.Upstream ||
		a.HTTPChallengeUpstream != b.HTTPChallengeUpstream || (a.Claim == nil) != (b.Claim == nil) {
		return false
	}
	return a.Claim == nil || *a.Claim == *b.Claim
}

func loadTLSMaterial(cert *clientCert) (*tlsMaterial, error) {
	tlsCert, err := tls.X509KeyPair([]byte(cert.ClientCertPEM), []byte(cert.ClientKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("load X509 keypair: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(cert.CACertPEM)) {
		return nil, fmt.Errorf("CA cert PEM unusable")
	}
	return &tlsMaterial{certificate: tlsCert, rootCAs: pool}, nil
}

func (m *tlsMaterial) configForEndpoint(endpoint, serverNameOverride string) (*tls.Config, error) {
	serverName := serverNameOverride
	if serverName == "" {
		host, _, err := net.SplitHostPort(endpoint)
		if err != nil {
			return nil, fmt.Errorf("derive TLS ServerName from %q: %w", endpoint, err)
		}
		serverName = host
	}
	config := &tls.Config{
		RootCAs:    m.rootCAs,
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	}
	if m.getClientCertificate != nil {
		config.GetClientCertificate = m.getClientCertificate
	} else {
		config.Certificates = []tls.Certificate{m.certificate}
	}
	return config, nil
}

func runWorker(ctx context.Context, log *slog.Logger, plan workerPlan, token string, dialer contextDialer, tlsConfig *tls.Config) {
	backoff := time.Second
	for ctx.Err() == nil {
		sessionDuration, err := runOnce(ctx, log, plan.RelayAddr, token, plan.Claim, plan.Upstream, plan.HTTPChallengeUpstream, dialer, tlsConfig)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Warn("tunnel error", "err", err, "relay", plan.RelayAddr, "subscription_id", plan.SubscriptionID)
		}
		if sessionDuration >= stableSessionDuration {
			backoff = time.Second
		}
		delay := jitter(backoff)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
		if backoff < 30*time.Second {
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
}

func runWorkerPlans(plans []workerPlan, run func(workerPlan)) {
	var workers sync.WaitGroup
	for _, plan := range plans {
		workers.Add(1)
		go func(plan workerPlan) {
			defer workers.Done()
			run(plan)
		}(plan)
	}
	workers.Wait()
}

func jitter(duration time.Duration) time.Duration {
	quarter := duration / 4
	if quarter == 0 {
		return duration
	}
	return duration - quarter + time.Duration(rand.Int63n(int64(quarter*2)+1))
}
