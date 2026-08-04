# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.3] - 2026-08-04

### Added

- Blindport Relay for publishing TLS services through managed or customer-owned
  hostnames without terminating customer TLS.
- Blindport Port for forwarding one shared public TCP or UDP endpoint, and
  Blindport IP for either low-privilege framed TCP forwarding or a complete
  routed public IPv4 interface through WireGuard.
- Anonymous bearer-token accounts with opaque public identifiers, monthly or
  yearly service terms, direct Lightning payments, optional NWC automatic
  renewal, and optional SMTP expiration reminders.
- A responsive dashboard and admin control panel for orders, payments, client
  setup, account status, and service statistics.
- Linux `blindportd` binaries and containers with static mappings, Docker
  discovery, native routed WireGuard, and optional Tor SOCKS5 transport.
- End-to-end mutual TLS between agents and relays, GPG-signed source releases,
  checksummed CI-built binaries, multi-architecture GHCR images, and
  digest-pinned deployment references.
