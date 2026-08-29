package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
)

type accountRuntime struct {
	name        string
	tokenFile   string
	stateDir    string
	mappings    []mapping
	coordinator *provisioningCoordinator
	options     framedRuntimeOptions
}

type accountRuntimeRunner func(context.Context, *slog.Logger, accountRuntime) error

type accountProvisioner func(context.Context, *slog.Logger, accountRuntime, string) error

func newAccountRuntimes(accounts []staticAccount, options framedRuntimeOptions) []accountRuntime {
	runtimes := make([]accountRuntime, 0, len(accounts))
	for _, account := range accounts {
		mappings := append([]mapping(nil), account.Mappings...)
		for i := range mappings {
			mappings[i].AccountName = account.Name
		}
		accountOptions := options
		accountOptions.accountName = account.Name
		accountOptions.stateDir = account.StateDir
		runtimes = append(runtimes, accountRuntime{
			name:        account.Name,
			tokenFile:   account.TokenFile,
			stateDir:    account.StateDir,
			mappings:    mappings,
			coordinator: newMappingProvisioningCoordinator(mappings, options.relayOverride, false),
			options:     accountOptions,
		})
	}
	return runtimes
}

func runStaticAccountRuntimes(ctx context.Context, logger *slog.Logger, accounts []staticAccount, outbound *outboundTransport, options framedRuntimeOptions) error {
	return runPreparedAccountRuntimes(ctx, logger, accounts, outbound, options, func(runtimeCtx context.Context, accountLogger *slog.Logger, runtime accountRuntime, token string) error {
		return runFramedProvisioner(runtimeCtx, accountLogger, token, outbound, runtime.coordinator, runtime.options)
	})
}

func runDockerAccountRuntimes(ctx context.Context, logger *slog.Logger, accounts []staticAccount, docker dockerContainerLister, outbound *outboundTransport, options framedRuntimeOptions) error {
	accountNames := make([]string, len(accounts))
	for index, account := range accounts {
		accountNames[index] = account.Name
	}
	options.dockerAccountNames = accountNames
	discovery, err := newSharedDockerDiscovery(docker, accounts, options.pollInterval)
	if err != nil {
		return err
	}
	options.dockerDiscovery = discovery
	return runPreparedAccountRuntimes(ctx, logger, accounts, outbound, options, func(runtimeCtx context.Context, accountLogger *slog.Logger, runtime accountRuntime, token string) error {
		return runDockerFramed(runtimeCtx, accountLogger, docker, runtime.mappings, token, outbound, runtime.options)
	})
}

func runPreparedAccountRuntimes(ctx context.Context, logger *slog.Logger, accounts []staticAccount, outbound *outboundTransport, options framedRuntimeOptions, provision accountProvisioner) error {
	if provision == nil {
		return errors.New("account provisioner is required")
	}
	runtimes := newAccountRuntimes(accounts, options)
	return runAccountRuntimes(ctx, logger, runtimes, func(runtimeCtx context.Context, accountLogger *slog.Logger, runtime accountRuntime) error {
		token, err := loadStaticAccountToken(runtime.tokenFile)
		if err != nil {
			return fmt.Errorf("load account token: %w", err)
		}
		if err := prepareCredentialStateDir(runtime.stateDir); err != nil {
			return fmt.Errorf("initialize account state: %w", err)
		}
		notifyAgentUpdate(runtimeCtx, accountLogger, outbound.httpClient, runtime.options.backend, token)
		return provision(runtimeCtx, accountLogger, runtime, token)
	})
}

func runAccountRuntimes(ctx context.Context, logger *slog.Logger, runtimes []accountRuntime, run accountRuntimeRunner) error {
	if len(runtimes) == 0 || run == nil {
		return errors.New("account runtimes are required")
	}
	runtimeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		accountName string
		err         error
	}
	results := make(chan result, len(runtimes))
	var workers sync.WaitGroup
	for _, runtime := range runtimes {
		workers.Add(1)
		go func(runtime accountRuntime) {
			defer workers.Done()
			results <- result{accountName: runtime.name, err: run(runtimeCtx, logger.With("account", runtime.name), runtime)}
		}(runtime)
	}

	unsuccessful := 0
	failures := make([]error, 0, len(runtimes))
	for range runtimes {
		result := <-results
		if ctx.Err() == nil {
			if result.err != nil {
				unsuccessful++
				failure := fmt.Errorf("account %q: %w", result.accountName, result.err)
				failures = append(failures, failure)
				logger.Error("account runtime stopped", "account", result.accountName, "err", result.err)
			} else {
				logger.Warn("account runtime stopped", "account", result.accountName)
			}
		}
	}
	workers.Wait()
	if ctx.Err() != nil {
		return nil
	}
	if unsuccessful == len(runtimes) {
		return fmt.Errorf("all %d account runtimes terminated unsuccessfully: %w", len(runtimes), errors.Join(failures...))
	}
	return nil
}
