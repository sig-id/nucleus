# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
- No unreleased changes.

## [0.3.9] - 2026-06-30

### Added
- **Rootless user-namespace mapping** (`--userns keep-id|auto|nomap`) with
  Docker/Podman-compatible `/etc/subuid` + `/etc/subgid` lookup and explicit
  `--uidmap`/`--gidmap` (`container:host:size`) support. `keep-id` maps the
  calling user's uid to itself so bind-mounted host files keep working, and is
  auto-selected when `--user <non-zero>` is requested — closing the gap that
  prevented euid-0-refusing workloads (e.g. PostgreSQL) from running rootless.
  Multi-entry maps are written through the setuid `newuidmap`/`newgidmap`
  helpers.
- **Rootless gVisor**: the gVisor runtime's artifact-directory security checks
  are now user-namespace-aware, so `--runtime gvisor --userns keep-id` runs
  workloads unprivileged (previously gVisor rootless only worked with the
  identity `nomap` mapping, which cannot run non-root workloads).
- GPU passthrough support.
- Image snapshotting.
- Egress credential broker for untrusted sandboxes that need bearer-token API
  access; the broker runs host-side and Nucleus installs deny-by-default egress
  rules allowing only the broker endpoint.
- PTY console attachment, sandbox lifecycle event streaming, policy mounts, and
  workspace mounts.
- `gVisor-host` network mode (runsc `hostinet`) as the gVisor path to host
  networking, distinct from native `--network host`.
- gVisor variant in the PostgreSQL 18 benchmark (`benches/pg18_io`), now
  runnable fully rootless (`ROOTLESS=1`).

### Fixed
- Numerous gVisor rootless and networking correctness fixes: runsc rootless
  re-exec via `/proc/self/exe`, platform preservation, ptrace-cap retention
  for systrap, NixOS uidmap-wrapper exposure, nested-userns avoidance for
  bridge, and supervisor exec policy.
- File-descriptor sanitization across namespace setup.
- Rootfs assembly writability and Nix store closure mounting.
- gVisor runtime handling for non-root launches and host networking.

## [0.3.6] - 2026-05-06

### Fixed
- Include the gVisor `runsc` executable-path patch in the Nix flake source.

## [0.3.3] - 2026-04-08

### Added
- Detached mode (`-d`/`--detach`) for running containers as systemd transient services.
- `nucleus logs` for detached-container journal access, including follow and tail support.
- Userspace NAT and `slirp4netns` bridge fallback support.
- PostgreSQL 18 benchmark harness and updated performance documentation.
- Opt-in seccomp syscall extensions via `--seccomp-allow`.
- Memlock resource control plumbing.

### Fixed
- gVisor runtime handling and network-mode integration.
- Capability dropping and seccomp filter correctness.
- Audit-path hardening and benchmark reporting polish.

## [0.3.2] - 2026-04-07

### Fixed
- Audit hardening and release polish.

## [0.3.1] - 2026-04-07

### Added
- Volume mounts for workloads.
- Environment-variable injection and benchmark updates.
- Workload identity controls via UID/GID privilege drop.

### Fixed
- gVisor Nix integration.
- A runtime memory leak.
- Audit hardening follow-ups.

## [0.3.0] - 2026-04-06

### Added
- Initial public Nucleus runtime release.
- Native and gVisor runtimes, rootless mode, stats/ps lifecycle commands, cgroup v2 controls, and namespace isolation.
- Landlock, seccomp, capability, and production-mode hardening.
- Multi-tenant container support, integration tests, audit logging, and benchmark tooling.

## [0.2.1] - 2026-04-05

### Fixed
- AArch64 compatibility for release artifacts.

## [0.2.0] - 2026-04-05

### Added
- First tagged crate release with the baseline container runtime functionality.
