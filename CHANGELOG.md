# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
- Added: `--allow-jit` (launch config `allow_jit`): a per-launch JIT allowance
  for the native seccomp filter. JIT runtimes (V8/Node, JVM, PyPy, LuaJIT, .NET)
  manage code ranges that are writable and executable at once; V8 has no
  fallback for a denied RWX range, so the default W^X policy killed every
  Node workload with `SIGSYS` before user code ran (#46). The allowance
  permits write+execute mappings through `mmap`, `mprotect`, and
  `pkey_mprotect` (no separate `--seccomp-allow pkey_mprotect` needed), keeps
  every other memory guard enforced (executable `shmat` attachments,
  `memfd_create`, device nodes), works with built-in and custom profiles, is
  rejected under gVisor, and is recorded in the audit log and reported as
  `security.allow_jit` in `container_started`/`container_summary` so callers
  can attest the posture. W^X stays the default.

## [0.6.0] - 2026-11-19

### Added
- `--start-fd FD` (launch config `start_fd`): an opt-in start gate for
  `run`. After setup completes, Nucleus emits `container_started` and the
  container's init blocks reading one byte from the inherited descriptor,
  like the OCI exec FIFO; the workload execs only when the byte arrives, so
  an orchestrator can verify the reported posture first. On EOF without a
  byte the container is torn down and Nucleus exits non-zero without running
  the workload. A `SIGTERM` to the supervisor while the workload is held
  cancels the hold and tears down the same way (exit status 143), so a held
  container is never unkillable (#42).
- `--broker-proxy-listen 127.0.0.1:PORT` (launch config `broker_proxy_listen`)
  runs the broker forwarder in the supervisor. The container init binds the
  listener in its network namespace and hands it over with `SCM_RIGHTS`; the
  supervisor relays each connection to the verified broker socket inode. The
  socket is no longer mounted, the workload needs no forwarder binary, proxy
  variables are injected unless `--no-broker-proxy-env`, and
  `container_started` reports the address (#39).
- `--memory-high SIZE` (launch config `memory_high`) sets an explicit memory
  throttling watermark; it must not exceed `--memory`.
- `container_summary` resource stats include `memory_events` (`high`, `max`,
  `oom`, `oom_kill`) so callers can tell a memory failure from other exits.

### Fixed
- `SIGTERM` to a foreground `nucleus run` supervisor killed the supervisor
  outright instead of being forwarded: glibc's `sigwait` unblocks the waited
  signal set in the calling thread, so the forwarding thread became the one
  thread where the signal's default disposition ran. The forwarded-signal
  set is now blocked before the first helper thread is spawned (every
  thread inherits the mask) and consumed with `sigtimedwait`, which never
  touches the mask. `SIGTERM` now reaches the container's init, which can
  shut the workload down gracefully; a workload that is PID 1 of its PID
  namespace and installs no handler still ignores it (as with any OCI
  runtime) — use `SIGKILL` for a guaranteed teardown.
- `--memory` no longer sets `memory.high` to 90% of the limit. With swap
  disabled that throttled a runaway workload just below the limit almost
  indefinitely; it is now OOM-killed at `memory.max` (#37).
- After a supervisor SIGKILL the reaper also removes the gVisor state and
  bundle directory under `nucleus-gvisor/<id>` (#38).
- Delegated cgroups of the systemd user manager are detected. The user manager
  sets no `delegate` xattr, so for a service or scope under
  `user@<uid>.service` Nucleus reads the unit's `Delegate` property with
  `systemctl --user show`. Strict modes now get resource enforcement under
  `systemd-run --user [--scope] -p Delegate=yes` without `NUCLEUS_CGROUP_ROOT`.
  The strict-mode cgroup error names `Delegate=` and `NUCLEUS_CGROUP_ROOT`, and
  the README documents `NUCLEUS_CGROUP_ROOT` for layouts that are not detected
  (#34).
- A native workload whose command cannot be executed (for example a missing
  binary) fails with `Failed to execute <command>: <errno>` and exit status 1.
  Before, the setup process unwound into a tmpfs unmount after seccomp was
  installed and was killed with `SIGSYS` (exit 159) without an error message.

### Changed
- **Breaking:** `--broker-socket` is refused under gVisor, which could only reach the
  socket with `--host-uds=open` and so let the sandbox connect to every host
  socket in its mounts. Untrusted workloads with a broker need
  `--trust-level trusted --runtime native` (#36).
- The native seccomp filter refuses namespace creation (`unshare` or `clone`
  with `CLONE_NEW*` flags, and `setns`) with `EPERM` instead of killing the
  workload with `SIGSYS`, so nested sandboxes such as bubblewrap report an
  error. The README documents that nested sandboxes do not work under either
  runtime (#35).

## [0.5.3] - 2026-11-19

### Added
- `--quiet` keeps Nucleus off the workload's stdio: the container ID is not
  printed on stdout and stderr logging defaults to errors. `--events-fd` and
  `create --config-fd` imply it; the ID is reported in the event stream.
- `--broker-socket PATH` for rootless brokered egress: one host unix socket is
  mounted at `/run/nucleus/broker.sock` (`NUCLEUS_BROKER_SOCKET`) in a container
  that keeps `--network none`. Loopback is raised and IP sockets are allowed so
  an in-container proxy forwarder can listen on `127.0.0.1`. Under the native
  runtime Landlock confines pathname socket connections to that socket (kernel
  ABI 9 or later); gVisor is started with `--host-uds=open`.
- Bind volumes accept a `caller-owned` option (`SOURCE:DEST:rw,caller-owned`)
  that admits a directory owned by the calling user under `/home`, `/tmp`,
  `/run` or `/var/lib`.
- Container cgroups are created in the caller's delegated subtree when systemd
  marks one (`Delegate=`, optionally `DelegateSubgroup=`), and the needed
  controllers are enabled there, so strict modes get resource enforcement
  without root. `NUCLEUS_CGROUP_ROOT` roots get the same controller setup.

### Changed
- `--events-fd` no longer prints the container ID on stdout, and `--events-fd`
  and `create --config-fd` log only errors to stderr by default. Set `RUST_LOG`
  or `--log` for the previous verbosity.
- The `network_mode` field of control events is `broker-socket` in that mode.

### Fixed
- Killing only the supervisor no longer orphans the workload. Container setup
  processes die with their parent, and a detached reaper kills and removes the
  container cgroup when the supervisor is gone.
- gVisor bind mounts of non-regular files (such as sockets) get a file
  mountpoint instead of a directory.
- OCI hooks run in user-namespaced native containers (rootless, and root-run
  production containers, which are root-remapped). Their trust checks ran
  after entering the user namespace, where host-root-owned binaries and
  directories appear unmapped, so every hook was refused.
  - `createRuntime` hooks resolve in the runtime namespace: they are now
    validated under the host credentials before the namespaces are created,
    and refused at run time if the validated executable was replaced.
  - `createContainer` and `startContainer` hooks resolve inside the
    container. Their owner check now also trusts owners outside the
    container's user namespace, which nothing inside it can act as; the
    group/world-writable and setuid checks still apply. An owner is only
    provably outside when the namespace leaves the overflow UID unmapped.
    Under a mapping that includes it (root remapping and other 65,536-ID
    maps), a host-owned hook is indistinguishable from one owned by a user
    inside the namespace and is still refused.

## [0.5.2] - 2026-11-19

### Fixed
- Rootless gVisor containers start again when `NUCLEUS_RUNSC_DEBUG_DIR` is
  set. 0.5.0 checked the debug directory's ancestors after entering the
  launch's user namespace, where host-root-owned directories such as `/var`
  appear unmapped, so every start failed with `Untrusted directory "/var"
  (uid 65534)`. The directory is now validated under the host credentials
  before the handoff.
- The Nix flake no longer warns that `buildDepsOnly` ignores `src` on every
  evaluation.

### Security
- Trusted-directory and OCI hook owner checks report an owner that is not
  mapped into the current user namespace as such, and reject it. Previously,
  in a namespace without an ID map the caller's own UID was the overflow UID
  too, so every directory appeared caller-owned and passed the check.

## [0.5.1] - 2026-11-19

### Fixed
- The Nix flake package builds again. It no longer runs the test suite, which
  recompiled dependencies the cached artifacts already held; tests run once in
  the `my-crate-nextest` check, which skips the four tests that need host
  semantics the Nix build sandbox withholds (setid `chmod`, a root-owned `/nix`
  for hook trust checks). CI still runs those four, and now also builds the
  package and nextest check so a sandbox-only failure blocks the merge.
- The dependency-only Nix build no longer emits a spurious unused-dependency
  warning for every dependency of its stubbed sources.
- The Nix package version comes from `Cargo.toml` instead of a stale `0.4.0`.

## [0.5.0] - 2026-11-19

### Security
- Enforce the workload cgroup, identity and saved seccomp program for native
  attach and probe helpers, run timed probes in private sessions, and reap
  their descendants.
- Restrict futex operations in the native seccomp filter, denying all
  priority-inheritance commands, and limit `socketpair()` to the Unix domain
  while denying `TCP_ULP` at the TCP level.
- Remap root-launched containers to exclusive, atomically claimed host UID and
  GID blocks instead of the shared fixed range, and strip set-user-ID and
  set-group-ID bits from workspace copy-in and copy-out.
- Require authenticated private snapshots for image imports, open mount
  targets component by component without following image symlinks, and apply
  recursive bind-mount restrictions before the mount tree becomes visible
  (Linux 5.12 or later).
- Deny all bridge traffic by default in every service mode and require
  successful firewall installation before the workload is released.
- Apply write/execute checks to `mmap`, `mprotect` and opt-in `pkey_mprotect`,
  make executable SysV shared-memory attachments read-only, and clear inherited
  `READ_IMPLIES_EXEC`.
- Deny `PR_SET_MM` options, `mknod`, `pidfd_getfd`, `open_by_handle_at`,
  `kcmp`, `syslog` and clock setters in native policies, and require explicit
  opt-in for `splice`, `tee` and `sendfile` in every network mode.
- Preserve legacy terminal ioctls in GPU mode while blocking `TIOCSTI` and
  `TIOCLINUX` on inherited descriptors.
- Bind only `/nix/store` from the host Nix installation in native agent mode
  and enforce the GPU device allowlist with a cgroup-device eBPF program.
- Check bind sources against sensitive directories, verify the selected rootfs
  and its store objects against the host Nix database, and mount native procfs
  with `hidepid=2,subset=pid`.
- Enforce configured minimum Landlock ABIs with ABI 6 scoping for
  host-network workloads, scope abstract Unix sockets and signals, and verify
  all five capability sets against kernel state.
- Isolate bridge ports by default, scope masquerade to traffic leaving the
  bridge, publish ports only on local destinations, and run `slirp4netns` as
  mapped root with mandatory sandbox and seccomp filters.
- Require explicit DNS egress grants, resolve them on the host, reject
  protected answers, and expire permitted resolvers in the kernel.
- Sign image content and metadata with Ed25519, support public-key-only
  verification, and validate OCI hook executables and their ancestors while
  dropping their capabilities and enforcing no-new-privileges.
- Pin checkpoint directories for HMAC verification and CRIU execution,
  enforce supervisor ownership, and scope seccomp trace records by audit PID,
  descendants, cgroup and PID namespace.
- Route state directories through the trusted-directory gate, rejecting
  foreign-owned roots even for host root.
- Resolve `/proc/self` and descriptor links again by removing the mount-wide
  `nosymfollow` flag while keeping execution blocked at the `execveat`,
  Landlock and mount-noexec decision points, and fail closed unless every
  workload proc mount carries `nosuid,nodev,noexec`.
- Mount `/tmp` as a dedicated `noexec,nosuid,nodev` tmpfs reserved against
  volume overrides.
- Allowlist `setsockopt` levels with per-level carve-outs denying `TCP_ULP`
  and `UDP_ENCAP`, and deny `MSG_OOB` on message sends and receives.

### Added
- Per-topology bridge networks with distinct names and configured subnets.
- Ed25519 image signing with cross-host verification instructions.
- NixOS `environmentFile` support for passing private runtime configuration to
  supervisors.

### Changed
- Require Rust 1.100 and refresh the Cargo and Nix dependency graphs.
- Run gVisor bridge networking on the sandbox network stack, pin runsc
  20261116.0 in the flake, and reject unversioned builds or releases older
  than 20260831.0.
- Require nftables and `net.ipv4.ip_forward=1` for the kernel bridge backend;
  unmarked bridges from earlier versions require migration, and DNS egress now
  requires `--egress-dns` with `--dns`.
- Default NixOS supervisors to per-unit dynamic users with bounded
  capabilities, syscall and namespace restrictions; remove the unrestricted
  `extraArgs` option.
- Reject automatically root-remapped containers and legacy namespaces with
  unknown mappings in CRIU checkpoint and restore; recreate existing
  root-remapped containers to receive fresh exclusive ID mappings and preserve
  the reservation registry across upgrades.

### Fixed
- Deny `FICLONE`/`FICLONERANGE` ioctl probes with `EOPNOTSUPP` so coreutils
  `cp` falls back to a read/write copy instead of dying with `SIGSYS` on
  current distributions.
- Fall back to a staging file when the kernel rejects memfd `resolv.conf`
  binds, and keep the staged file readable by non-root workloads.
- Remove deleted workspace directories through the pinned descriptor rather
  than the procfs link.
- Recover from kernel log overruns without discarding seccomp trace records.

## [0.4.0] - 2026-09-09

### Security
- Restrict explicit GPU passthrough to recognized GPU character devices under
  `/dev`, rejecting arbitrary character and block devices.
- Create independent container GPU device nodes with workload ownership and
  mode `0660`, preserving non-root GPU access without changing host ownership
  or permissions. Native setup now fails if device creation or ownership
  assignment is unavailable, or a target inode already exists.

### Changed
- Upgrade Rust dependencies, including `dirs` 7, and refresh all transitive
  dependency versions. Adopt the current Landlock `no_new_privs` API.
- Refresh Nix inputs and the PostgreSQL benchmark lockfile.

### Fixed
- Place native GPU devices at their expected `/dev/...` paths instead of
  `/dev/dev/...`.
- Isolate image-signing keys in unit and integration tests to prevent parallel
  key-creation races on clean systems.
- Satisfy the current stable Clippy byte-string lint.

### Tests
- Add a privileged CI regression test verifying root and non-root access to
  private device nodes while preserving the source inode's metadata.

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
