# Nucleus

[![Crates.io](https://img.shields.io/crates/v/nucleus-container.svg)](https://crates.io/crates/nucleus-container)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

**Extremely lightweight, security-hardened, declarative container runtime for agents and production services**

Nucleus is a minimalist container runtime for Linux. It provides isolated execution environments using Linux kernel primitives without the overhead of traditional container runtimes. For production services, it is designed around a fully declarative model: Nix builds the root filesystem or image, the NixOS module declares the service, and Nucleus mounts pinned, reproducible runtime inputs.

Nucleus supports three operating modes:

- **Agent mode** (default) – ephemeral, fast-startup sandboxes for AI agent workloads
- **Strict agent mode** – fail-closed isolation for ephemeral agent workloads without requiring production rootfs, health checks, sd_notify, or NixOS service semantics
- **Production mode** – strict isolation for long-running, network-bound NixOS services with declarative configuration, reproducible Nix-built root filesystems/images, egress policy enforcement, health checks, and systemd integration

Production deployments are built to be:

- **Fully declarative** – service topology, runtime settings, mounted rootfs, and optional images are defined up front instead of assembled imperatively at deploy time
- **Nix-native** – first-class NixOS module support plus `nucleus.lib.mkRootfs` and `nucleus.lib.mkImage` for minimal service closures
- **Reproducible** – flake-based builds, pinned store paths, rootfs attestation, and image signatures keep runtime inputs stable and auditable

## Benchmarks

### Cold Start

| Runtime | Startup Time |
|---|---|
| **Nucleus** | **12 ms** |
| Docker | ~500 ms |

### PostgreSQL 18 (pgbench, 8 clients, 60s, scale 50)

In the native runtime, PostgreSQL stays near bare-metal performance under Nucleus
isolation. In this harness, occasional wins over bare metal should be treated as
benchmark noise rather than a guaranteed speedup.

**SELECT-only (read-heavy)**

| Environment | I/O Method | Avg TPS | Avg Latency |
|---|---|---|---|
| Baremetal | worker | 100,222 | 0.080 ms |
| Baremetal | io_uring | 84,895 | 0.096 ms |
| **Nucleus** | **worker** | **105,965** | **0.075 ms** |
| **Nucleus** | **io_uring** | **107,039** | **0.074 ms** |

**TPC-B (mixed read/write)**

| Environment | I/O Method | Avg TPS | Avg Latency |
|---|---|---|---|
| Baremetal | worker | 1,490 | 5.38 ms |
| Baremetal | io_uring | 1,382 | 5.79 ms |
| **Nucleus** | **worker** | **1,757** | **4.55 ms** |
| **Nucleus** | **io_uring** | **1,585** | **5.05 ms** |

> Measured on Linux 6.18 x86_64. This benchmark uses the native runtime with a
> bind-mounted host `pgdata` directory and `--network host`, so it measures the
> steady-state cost of Nucleus isolation rather than VM or gVisor emulation
> overhead. Full results: [`benches/pg18_io/results/`](benches/pg18_io/results/)

## Why Nucleus?

- **Declarative by default for services** – Production deployments are defined in NixOS and TOML rather than stitched together with ad hoc runtime scripting
- **Deep Nix integration** – First-class NixOS module, `mkRootfs`, `mkImage`, and Nix store closures for minimal, locked-down service roots
- **Reproducible service builds** – Flake-based packaging, pinned inputs, rootfs attestation, and image signatures make runtime state auditable and repeatable
- **Zero-overhead isolation** – Direct use of cgroups, namespaces, pivot_root, capabilities, seccomp, and Landlock
- **Memory-backed filesystems** – Container disk mapped to tmpfs, pre-populated with agent context
- **gVisor integration** – Optional application kernel for enhanced security, including networked service mode
- **OCI runtime-spec subset for gVisor** – Generates OCI bundle/config data for `runsc`, including process identity, mounts, namespaces, seccomp, hooks, and cgroup path wiring
- **Detached mode** – Run containers in the background as systemd transient services with `--detach`, managed via `nucleus stop`/`logs`/`attach`
- **Production service support** – Declarative NixOS module, egress policies, credential-broker egress, health checks, secrets mounting, sd_notify, and journald integration
- **Explicit workload identity** – Native and gVisor runtimes can drop to a configured `uid`/`gid` plus supplementary groups after privileged setup
- **Minimal rootfs** – Replace host bind mounts with a purpose-built Nix store closure or Nix-built image for production services
- **Local image snapshots** – Commit native overlay-backed containers to signed, thin image directories, then verify, inspect, and run them later
- **External security policies** – Per-service seccomp profiles (JSON), capability policies (TOML), and Landlock rules (TOML) with SHA-256 pinning
- **Seccomp profile generation** – Trace mode records syscalls, then `nucleus seccomp generate` creates a minimal allowlist profile
- **Multi-container topologies** – Compose-equivalent TOML format with dependency DAG, reconciliation, and NixOS systemd integration
- **Integrity & audit controls** – Structured audit log, machine-readable lifecycle event streams, context hashing, rootfs attestation, image signatures, seccomp deny logging, mount flag verification, and kernel lockdown assertions
- **Structured telemetry** – Optional OpenTelemetry export for container lifecycle tracing
- **Linux-native** – Runs on standard Linux and NixOS

## Relationship to Docker

Nucleus is **not** a drop-in Docker replacement, nor a strict subset of Docker.
The feature sets overlap, but each tool does things the other does not. Nucleus is
a hardened sandbox runtime (closer in spirit to `runc`/`gVisor`) that also does
lightweight, declarative single-host orchestration. It drops Docker's build DSL,
registry, and distribution workflow in exchange for deeper isolation, policy,
and reproducibility. Local signed image snapshots are available, but they are
not Docker/OCI images.

| Capability | Docker | Nucleus |
|---|---|---|
| Root filesystem | Layered image (union mount) | tmpfs directory (agent), Nix closure (production), or overlay-backed Nix closure for snapshots |
| Images / Dockerfile / registry | Yes | Signed local thin snapshots and Nix-built image manifests; no Dockerfile, registry, `pull`/`push`, or OCI *image* spec |
| Persistent storage | Named volumes + storage drivers | Ephemeral tmpfs; persistence only via explicit `--volume` binds |
| Architecture | `dockerd` daemon + socket API | Single binary, direct fork/exec; detached = systemd transient unit |
| Networking | CNI plugins, overlay networks | `none` / `host` / `bridge` only |
| Orchestration | Compose, Swarm | `nucleus compose` (single-host TOML DAG over systemd) |
| Default egress | Allow-all outbound | Deny-by-default; allow per CIDR/domain via namespace iptables |
| Filesystem ACLs | AppArmor/SELinux profiles | Landlock LSM, per-service, irreversible |
| gVisor | Optional add-on runtime | First-class integrated runtime with explicit network modes |
| Security policies | Bundled defaults | Externalized seccomp/caps/Landlock, SHA-256 pinned + trace-generated |
| Reproducibility | Image digests | Nix closures, rootfs attestation, image signatures, first-class NixOS module |
| Verification | — | TLA+ specs + model-based tests across subsystems |
| Default hardening | ~300 syscalls, some caps kept | All caps dropped, small seccomp allowlist, up to 8 namespaces |

If your mental model is "run my Docker image instead of `docker run`," it will
not fit: there is no Dockerfile, registry, pull/push lifecycle, or implicit
persistent state. Nucleus images are local signed snapshots or Nix-built
manifests over Nix rootfs closures. If your model is "run untrusted or ephemeral
workloads with stronger, auditable isolation," that is the target.

## Architecture

Nucleus leverages Linux kernel isolation primitives:

- **Namespaces** – PID, mount, network, UTS, IPC, user, cgroup, and optional time isolation
- **cgroups v2** – Resource limits (CPU, memory, PIDs, I/O)
- **pivot_root** – Filesystem isolation (chroot fallback available in agent mode only)
- **Capabilities** – All capabilities dropped by default, or configured via TOML policy file (irreversible)
- **seccomp** – Syscall whitelist filtering with per-service JSON profiles and trace-based generation (irreversible)
- **Landlock** – Path-based filesystem access control via hardcoded defaults or TOML policy file (Linux 5.13+)
- **gVisor** – Optional application kernel (runsc) with none, bridge handoff, and explicit gvisor-host network modes
- **OCI bundle generation** – Emits OCI `config.json` plus bundle layout for gVisor, including `process.user`, lifecycle hooks, seccomp, resource limits, and namespace mappings
- **Image snapshots** – Local signed manifests with optional overlay diffs rooted in attested Nix rootfs closures
- **PID 1 init** – Mini-init supervisor in production mode for zombie reaping and signal forwarding
- **In-memory secrets** – Dedicated tmpfs at `/run/secrets` with volatile zeroing of source buffers
- **Mount audit** – Post-setup verification of mount flags in production mode

Container filesystem is backed by tmpfs and either populated with context files (agent mode) or mounted from a pre-built Nix rootfs closure (production mode). Snapshot workflows can mount that Nix rootfs with a writable native overlay and commit the overlay upperdir as a signed local image. That lets services run from declaratively built, reproducible filesystem inputs instead of inheriting mutable host state.

## Platform Support

- Linux (kernel 6.x+) on `x86_64`
- NixOS (first-class NixOS module support)
- **Not supported**: macOS, Windows, BSDs, 32-bit Linux

## Installation

```bash
cargo install nucleus-container
```

Or via Nix (recommended for reproducible builds and NixOS integration):

```bash
nix run github:wiggum-cc/nucleus
```

The Cargo package name is `nucleus-container`; it installs the `nucleus` binary. The repository itself is packaged as a Nix flake, so `nix run`, `nix build`, and the NixOS module all share the same pinned inputs.

## Recent Features

- **Local signed image snapshots** – Native overlay-backed containers can be committed, verified, inspected, loaded, and run as thin image directories over a Nix rootfs base.
- **Privilege drop for services** – `--user`, `--group`, and `--additional-group` now apply a real post-setup workload identity in both the native runtime and gVisor.
- **Ownership-aware secrets and writable paths** – Production secret staging and NixOS `createHostPath = true` defaults now align file ownership with the configured workload user/group.
- **OCI bundle identity support** – Generated gVisor OCI configs now carry `process.user` including supplementary groups, alongside namespaces, mounts, resource limits, seccomp, hooks, and `cgroupsPath`.
- **Probe execution under workload identity** – Exec-based health and readiness probes now run as the configured service account instead of implicitly as root.
- **Systemd/NixOS service integration improvements** – The module exposes `user`, `group`, and `supplementaryGroups`, and packaged Nix usage includes `gvisor` in the flake/dev shell path.

## Usage

### Agent Mode (default)

```bash
# Run agent in isolated container with pre-populated context
nucleus run --context ./agent-context/ -- /usr/bin/agent

# Specify resource limits
nucleus run --memory 512M --cpus 2 --context ./ctx/ -- ./agent

# Name your container
nucleus run --name my-agent --context ./ctx/ -- ./agent

# Use gVisor for enhanced isolation
nucleus run --runtime gvisor --context ./ctx/ -- ./agent

# Rootless mode
nucleus run --rootless -- /bin/sh

# Optional networking
nucleus run --network host --allow-host-network -- curl https://example.com
nucleus run --network bridge -p 8080:80 -- ./server
nucleus run --network bridge -p 127.0.0.1:8080:80 -- ./server
nucleus run --rootless --network bridge -- ./client
nucleus run --network bridge --nat-backend userspace -- ./client

# Context streaming (bind mount for instant access)
nucleus run --context ./large-dir/ --context-mode bind -- ./agent

# Integrity and audit hardening
nucleus run --context ./ctx/ --verify-context-integrity --seccomp-log-denied -- ./agent

# Environment variables
nucleus run -e DEBUG=1 -- ./agent

# Sensitive environment variables without argv exposure
printf '{"OPENAI_API_KEY":"..."}' | nucleus run --env-fd 3 3<&0 -- ./agent

# Pass sensitive values via --secret (mounted in-memory at /run/secrets)
nucleus run --secret /path/to/api-key:/run/secrets/api_key -- ./agent

# Run a coding agent against a stable /workspace cwd
nucleus run \
  --workspace "$PWD" \
  --workspace-mode bind-rw \
  --workspace-exec \
  -- ./agent

# Mount provider CLI config under the private home directory
nucleus run \
  --provider-config-ro "$HOME/.aws:.aws" \
  --provider-config-rw "$HOME/.config/gh:.config/gh" \
  -- ./agent

# Run an agent with a pinned provider/toolchain rootfs instead of host runtime binds
nucleus run \
  --service-mode mitos-agent \
  --agent-toolchain-rootfs /nix/store/...-nucleus-agent-toolchain-rootfs \
  --workspace "$PWD" \
  --workspace-exec \
  -- codex
```

### Programmatic Launch Config

`nucleus run` accepts the same command as `nucleus create`. Programmatic callers
that need a stable launch contract can provide the whole request as JSON or TOML
instead of constructing a long argv list:

```bash
nucleus run --config ./agent.nucleus.toml
nucleus run --config ./agent.nucleus.json
nucleus run --config-fd 3 3<./agent.nucleus.json
```

Config mode owns the launch request: put the workload command and all sandbox
options in the config document rather than mixing them with per-option CLI flags.
The schema uses the long CLI option names converted to `snake_case`:

```toml
name = "mitos-agent"
workspace = "/home/dev/project"
workspace_mode = "bind-rw"
workspace_exec = true
workdir = "/workspace"
runtime = "gvisor"
service_mode = "strict-agent"
agent_toolchain_rootfs = "/nix/store/...-nucleus-agent-toolchain-rootfs"
memory = "1G"
cpus = 2.0
pids = 512
command = ["./agent", "--stdio"]

env_vars = ["RUST_LOG=info"]
seccomp_log_denied = true
```

### Workspace

`--workspace <host-path>` mounts the host project tree at `/workspace`. The
process cwd defaults to `/workspace` via `--workdir /workspace`.

`--workspace-mode` accepts:

| Mode | Behavior |
|---|---|
| `bind-rw` | Bind mount the host path read-write at `/workspace` (default). |
| `bind-ro` | Bind mount the host path read-only at `/workspace`. |
| `copy-in-out` | Copy the host path into a private staging directory, run against that staged tree, then sync changes back after exit. |

Workspace mounts are `nosuid,nodev,noexec` by default and native Landlock denies
execution from `/workspace`. Use `--workspace-exec` for agent-mode workflows
that build and run test binaries from the workspace. Production mode rejects
writable executable workspaces; use an immutable `--rootfs` and explicit policy
files for production services.

### Sandbox Home and Provider Config

Nucleus creates a private tmpfs home at `/home/agent` by default and sets the
workload `HOME` to that path. The home tmpfs is mounted `nosuid,nodev,noexec`
with mode `0700` and is owned by the configured workload uid/gid. Use
`--home <container-path>` to choose a different private home path; the path must
be absolute and must not overlap `/workspace`.

Provider CLIs that require config under `$HOME` should use explicit provider
config mounts instead of broad host bind mounts:

```bash
nucleus run \
  --home /home/agent \
  --provider-config-ro "$HOME/.aws:.aws" \
  --provider-config-ro "$HOME/.config/gcloud:.config/gcloud" \
  --provider-config-rw "$HOME/.config/gh:.config/gh" \
  -- ./agent
```

`--provider-config-ro SOURCE:DEST` and `--provider-config-rw SOURCE:DEST` are
repeatable. `DEST` may be absolute under the configured home, or relative to the
home directory. Read-only mounts are preferred for cloud credentials; read-write
mounts are intended only for tools that must refresh local tokens.

### Agent Toolchain Rootfs

Mitos-style provider launchers can avoid depending on mutable host `/bin`,
`/usr`, `/lib`, or `/nix` binds by passing a pinned agent toolchain rootfs:

```bash
nucleus run \
  --service-mode strict-agent \
  --agent-toolchain-rootfs /nix/store/...-nucleus-agent-toolchain-rootfs \
  --workspace "$PWD" \
  --workspace-exec \
  -- claude
```

The dedicated flag is for `agent`, `strict-agent`, and `mitos-agent` modes. It
uses the same read-only rootfs mount path as `--rootfs`, but is rejected in
production mode so production services keep using `--rootfs` with attestation.

Build a rootfs with the Nix helper:

```nix
nucleus.lib.mkAgentToolchainRootfs {
  inherit pkgs;
  providerPackages = [
    # Derivations that provide claude/codex/gemini executables.
  ];
  extraPackages = [
    pkgs.rustc
    pkgs.cargo
  ];
}
```

The repository also exposes `packages.${system}.agent-toolchain-rootfs` as a
default shell/Git/compiler/package-manager rootfs. Integrations that need exact
provider CLIs should call `mkAgentToolchainRootfs` with pinned provider package
derivations and pass the resulting store path to `--agent-toolchain-rootfs`.

### Image Snapshots

Nucleus images are local directories containing a manifest, rootfs attestation,
store path list, optional overlay diff, and a signature for runtime-committed
images. They are not OCI/Docker images and are not pushed to or pulled from a
registry.

```bash
# Start an overlay-backed native container from a Nix rootfs
nucleus create -d \
  --name worker \
  --runtime native \
  --trust-level trusted \
  --rootfs /nix/store/...-worker-rootfs \
  --rootfs-mode overlay \
  -- /bin/sh -c 'echo committed > /tmp/result; sleep 3600'

# Commit the overlay upperdir as a signed thin image
nucleus image commit worker -o ./worker.nucleus-image

# Verify/load and inspect the image
nucleus image load ./worker.nucleus-image
nucleus image inspect ./worker.nucleus-image

# Run the manifest command, or override it after --
nucleus image run ./worker.nucleus-image -- /bin/cat /tmp/result
```

`nucleus image commit` requires a container launched with `--rootfs-mode
overlay`; overlay rootfs mode is currently native-runtime only and production
mode rejects it. Runtime-committed images are signed with a host-local HMAC key.
Set `NUCLEUS_IMAGE_HMAC_KEY_FILE` to pin that key path; otherwise Nucleus creates
an owner-only key under `/var/lib/nucleus` for root or the user's data directory
for non-root runs. Nix-built images from `nucleus.lib.mkImage` live in
`/nix/store` and omit `image.sig` because Nix store/substituter trust is the
integrity root.

### Detached Mode

Use `-d`/`--detach` to run a container in the background as a systemd transient service. The CLI prints the container ID and exits immediately; systemd supervises the container process.

```bash
# Run a container in the background
nucleus create -d --memory 512M -- /bin/sleep 3600
# prints: a1b2c3d4e5f6...

# All management commands work with detached containers
nucleus state                        # list running containers
nucleus logs <container>             # view stdout/stderr (from journald)
nucleus logs -f <container>          # follow logs
nucleus logs -n 50 <container>       # last 50 lines
nucleus attach <container>           # exec into it
nucleus stop <container>             # graceful SIGTERM → SIGKILL
nucleus kill <container>             # send signal

# Detach works with all create flags
nucleus create -d \
  --name my-service \
  --memory 1G --cpus 2 \
  --network bridge -p 8080:80 \
  -- ./my-server

# systemd unit is named nucleus-<id-prefix>
systemctl status nucleus-a1b2c3d4e5f6
journalctl -u nucleus-a1b2c3d4e5f6
```

The systemd transient service uses `KillMode=mixed` and `TimeoutStopSec=30`, so `systemctl stop` also works for graceful shutdown. The `--collect` flag ensures the unit is garbage-collected after the container exits.

### Production Mode

Production mode enforces strict security invariants:
- Forbids `--allow-degraded-security`, `--allow-chroot-fallback`, and native `--network host`
- Permits `--allow-host-network` only with `--network gvisor-host --runtime gvisor`
- Requires explicit `--memory` limit
- Requires successful cgroup creation (no fallback to running without limits)
- Egress policy failures are fatal where Nucleus owns the network namespace; `gvisor-host` cannot use Nucleus egress policy
- Bridge DNS must be configured explicitly (no public resolver defaults)

```bash
# Run a long-running service with production hardening
nucleus run \
  --service-mode production \
  --trust-level trusted \
  --memory 1G --cpus 2 --pids 256 \
  --rootfs /nix/store/...-my-service-rootfs \
  --verify-rootfs-attestation \
  --require-kernel-lockdown integrity \
  --network bridge --dns 10.0.0.1 \
  --egress-allow 10.0.0.0/8 \
  --egress-domain api.example.com \
  --egress-tcp-port 443 --egress-tcp-port 8443 \
  --health-cmd "curl -sf http://localhost:8080/health" \
  --health-interval 30 --health-retries 3 \
  --secret /run/secrets/tls-cert:/etc/tls/cert.pem \
  --systemd-credential db-url:/run/secrets/db-url \
  --volume /var/lib/myservice:/var/lib/myservice:rw \
  -e CONFIG_PATH=/etc/myservice/config.toml \
  --sd-notify \
  -p 127.0.0.1:8080:8080 \
  -- /bin/my-service --config /etc/myservice/config.toml

# gVisor with network access (sandbox network stack)
nucleus run \
  --service-mode production \
  --runtime gvisor \
  --gvisor-platform kvm \
  --memory 512M \
  --network bridge --dns 10.0.0.1 \
  --rootfs /nix/store/...-proxy-rootfs \
  -- /bin/proxy
```

### Strict Agent Mode

Strict agent mode (`--service-mode strict-agent`, `--service-mode mitos-agent`, or `--strict-agent`) keeps agent-style execution while making isolation setup fail closed:
- Forbids `--allow-degraded-security`, `--allow-chroot-fallback`, and native `--network host`
- Permits `--allow-host-network` only with `--network gvisor-host --runtime gvisor`
- Requires successful cgroup creation and successful application of configured limits
- Requires `pivot_root` in native mode; no `chroot` fallback
- Requires seccomp enforcement; `--seccomp-mode trace` is rejected
- Requires Landlock enforcement for native runtime
- Requires user namespace UID/GID mapping when running as host root or rootless
- Keeps network mode `none` by default; bridge mode requires explicit `--dns`

Strict agent mode does **not** require a production Nix rootfs, rootfs attestation, health checks, readiness probes, sd_notify, systemd transient services, or NixOS module deployment.

```bash
# Run an ephemeral agent with fail-closed native isolation
nucleus run \
  --service-mode strict-agent \
  --runtime native \
  --trust-level trusted \
  --memory 1G --cpus 2 \
  --context ./ctx \
  -- ./agent
```

### Security Policy Files

Nix defines the service and the root filesystem; separate files define security policy (what the process is allowed to do at the kernel level). This separation keeps deployments declarative, security config auditable, and runtime inputs reproducible without coupling policy changes to application rebuilds.

```bash
# Run with external security policies
nucleus run \
  --service-mode production \
  --rootfs /nix/store/...-my-service-rootfs \
  --memory 512M --cpus 1 \
  --seccomp-profile ./config/my-service.seccomp.json \
  --seccomp-profile-sha256 abc123... \
  --caps-policy ./config/my-service.caps.toml \
  --landlock-policy ./config/my-service.landlock.toml \
  -- /bin/my-service
```

**Seccomp profile** (JSON – OCI-native format, tooling emits it directly):
```json
{
  "defaultAction": "SCMP_ACT_KILL_PROCESS",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": ["read", "write", "close", "openat", "fstat",
                "mmap", "munmap", "brk", "futex", "clock_gettime"],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

**Capability policy** (TOML):
```toml
# config/my-service.caps.toml
[bounding]
keep = []          # empty = drop all

[ambient]
keep = []
```

**Landlock policy** (TOML):
```toml
# config/my-service.landlock.toml
min_abi = 3

[[rules]]
path = "/bin"
access = ["read", "execute"]

[[rules]]
path = "/etc/myservice"
access = ["read"]

[[rules]]
path = "/run/secrets"
access = ["read"]

[[rules]]
path = "/tmp"
access = ["read", "write", "create", "remove"]
```

### Seccomp Profile Generation

Profiles shouldn't be hand-written from scratch. Use trace mode to record actual syscall usage, then generate a minimal profile:

```bash
# 1. Run in trace mode – all syscalls allowed but logged
nucleus run \
  --seccomp-mode trace \
  --seccomp-log ./trace.ndjson \
  --rootfs /nix/store/...-my-service-rootfs \
  --memory 512M \
  -- /bin/my-service

# 2. Generate minimal profile from trace
nucleus seccomp generate ./trace.ndjson -o config/my-service.seccomp.json

# 3. Review and tighten (remove anything surprising)
# 4. Commit – Nix pins the SHA-256 hash
# 5. Run in enforce mode
nucleus run \
  --seccomp-profile ./config/my-service.seccomp.json \
  --seccomp-profile-sha256 "$(sha256sum config/my-service.seccomp.json | cut -d' ' -f1)" \
  -- /bin/my-service
```

Trace mode requires root or `CAP_SYSLOG` (reads `/dev/kmsg`). It is rejected in production mode – it is a development tool only.

### Multi-Container Topologies

Nucleus includes a Compose-equivalent for managing multi-container stacks using TOML configuration with dependency ordering.

```toml
# topology.toml
name = "myapp"

[networks.internal]
subnet = "10.42.0.0/24"

[volumes.db-data]
volume_type = "persistent"
path = "/var/lib/nucleus/myapp/db"
owner = "70:70"

[volumes.cache]
volume_type = "ephemeral"
size = "128M"

[services.postgres]
rootfs = "/nix/store/...-postgres"
command = ["postgres", "-D", "/var/lib/postgresql/data"]
memory = "2G"
cpus = 2.0
networks = ["internal"]
volumes = [
  "db-data:/var/lib/postgresql/data",
  "cache:/var/cache/postgresql"
]
health_check = "pg_isready -U myapp"

[services.web]
rootfs = "/nix/store/...-web"
command = ["/bin/web-server"]
memory = "512M"
networks = ["internal"]
nat_backend = "userspace"
port_forwards = ["8443:8443"]
egress_allow = ["10.42.0.0/24"]
egress_domains = ["api.example.com"]

[[services.web.depends_on]]
service = "postgres"
condition = "healthy"
```

```bash
# Validate topology and show dependency order
nucleus compose validate -f topology.toml

# Bring up all services in dependency order
nucleus compose up -f topology.toml

# Show service status
nucleus compose ps -f topology.toml

# Tear down in reverse dependency order
nucleus compose down -f topology.toml
```

### Container Management

```bash
# List running containers
nucleus ps

# List all containers (including stopped)
nucleus ps --all

# Show resource usage statistics
nucleus stats

# View logs for a detached container (from systemd journal)
nucleus logs <container>
nucleus logs -f <container>          # follow output
nucleus logs -n 100 <container>      # last 100 lines

# Stop a container (SIGTERM, then SIGKILL after timeout)
nucleus stop <container>
nucleus stop --timeout 30 <container>

# Kill a container with a specific signal
nucleus kill <container>
nucleus kill --signal TERM <container>

# Remove a stopped container
nucleus rm <container>
nucleus rm --force <container>

# Attach to a running container
nucleus attach <container>
nucleus attach <container> -- /bin/bash

# Checkpoint a running container (requires root, CRIU)
nucleus checkpoint <container> --output /path/to/checkpoint

# Restore from checkpoint
nucleus restore --input /path/to/checkpoint
```

## NixOS Module

Nucleus provides a declarative NixOS module for running containers as systemd services. Each container is managed as a `nucleus-<name>.service` unit with journald logging, sd_notify readiness, and automatic restart.

### Flake Setup

```nix
{
  inputs.nucleus.url = "github:wiggum-cc/nucleus";

  outputs = { self, nixpkgs, nucleus, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        nucleus.nixosModules.default
        ./configuration.nix
      ];
    };
  };
}
```

### Service Configuration

```nix
{ pkgs, nucleus, ... }:

let
  # Build a minimal rootfs containing only the packages your service needs.
  # This replaces host bind mounts with a locked-down Nix closure.
  proxyRootfs = nucleus.lib.mkRootfs {
    inherit pkgs;
    packages = [ my-proxy-pkg pkgs.cacert pkgs.curl ];
  };
in
{
  services.nucleus = {
    enable = true;
    package = nucleus.packages.x86_64-linux.default;

    containers.sigid-proxy = {
      enable = true;
      command = [ "/bin/sigid-proxy" "--config" "/etc/sigid/proxy.toml" ];
      rootfs = proxyRootfs;
      user = "sigid-proxy";
      group = "sigid-proxy";

      # Resource limits (required in production mode)
      memory = "1G";
      cpus = 2.0;
      pids = 256;

      # Security policy files (separate from Nix, auditable by security engineers)
      seccompProfile = {
        path = ./config/sigid-proxy.seccomp.json;
        sha256 = "abc123...";  # Nix verifies at build time
      };
      capsPolicy = ./config/sigid-proxy.caps.toml;
      landlockPolicy = ./config/sigid-proxy.landlock.toml;

      # Optional hardening toggles
      verifyRootfsAttestation = true;
      seccompLogDenied = true;
      requireKernelLockdown = "integrity";

      # Networking
      network = "bridge";
      natBackend = "auto";  # or "userspace" to force slirp4netns
      dns = [ "10.0.0.1" ];  # internal resolver – no public DNS default
      portForwards = [ "127.0.0.1:8080:8080" "127.0.0.1:8443:8443" ];

      # Egress policy – audited outbound access
      egressAllow = [ "10.0.0.0/8" ];
      egressDomains = [ "api.example.com" ];
      egressTcpPorts = [ 443 8443 ];

      # Credential broker alternative for bearer-token APIs.
      # Mutually exclusive with egressAllow / egressDomains above.
      # credentialBroker = "10.0.42.1:8080";
      # credentialBrokerNoProxyEnv = false;

      # Health checking
      healthCheck = "curl -sf http://localhost:8080/health";
      healthInterval = 30;
      healthRetries = 3;
      healthStartPeriod = 10;

      # Secrets (mounted read-only)
      secrets = [
        { source = config.age.secrets.proxy-tls.path; dest = "/etc/tls/cert.pem"; }
      ];

      # systemd-creds integration
      credentials = [
        {
          name = "proxy-key";
          source = config.age.secrets.proxy-key.path;
          dest = "/run/secrets/proxy-key";
          encrypted = false;
        }
      ];

      # Volumes (bind-mounted host paths)
      volumes = [
        {
          source = "/var/lib/sigid-proxy";
          dest = "/var/lib/sigid-proxy";
          createHostPath = true;
        }
      ];

      # Environment
      environment = {
        RUST_LOG = "info";
        CONFIG_PATH = "/etc/sigid/proxy.toml";
      };

      # systemd integration
      sdNotify = true;  # Type=notify, passes NOTIFY_SOCKET into container
    };
  };
}
```

Writable bind volumes are automatically added to the generated systemd unit's `ReadWritePaths`. When `createHostPath = true`, the NixOS module creates the host directory with `systemd-tmpfiles` before the container starts. If the container declares a workload `user`/`group`, those become the default tmpfiles owner for new writable paths unless the volume overrides them.

Credentials declared via `credentials = [ ... ]` use systemd's credential pipeline (`LoadCredential` or `LoadCredentialEncrypted`) and are mounted into the container through Nucleus's secret path. The CLI flag `--systemd-credential NAME:DEST` resolves `NAME` from `CREDENTIALS_DIRECTORY` at runtime.

For bearer-token API clients, the NixOS module exposes `credentialBroker = "IP:PORT";` and `credentialBrokerNoProxyEnv = true;`. This maps to `--credential-broker` and installs broker-only egress, so leave `egressAllow`, `egressDomains`, and egress port allowlists empty when using it.

Set `image = appImage;` instead of `rootfs = proxyRootfs;` when a service should
consume a Nix-built image produced by `nucleus.lib.mkImage`. `rootfs` and
`image` are mutually exclusive. When `command = [ ];`, the module uses the image
manifest command. The NixOS production launcher currently supports build-time
images without overlay diffs; committed runtime image diffs are a local CLI
workflow.

Set `user`, `group`, and optional `supplementaryGroups` on a NixOS container definition when the workload should run as a dedicated service account instead of root.

### Topology Services

Topologies can also be managed as systemd services:

```nix
{
  services.nucleus = {
    enable = true;
    package = nucleus.packages.x86_64-linux.default;

    topologies.myapp = {
      enable = true;
      configFile = ./topology.toml;
    };
  };
}
```

This creates a `nucleus-topology-myapp.service` (Type=oneshot, RemainAfterExit) that runs `nucleus compose up` on start and `nucleus compose down` on stop.

### What the Module Generates

For each enabled container, the module creates a systemd service:

- **Unit**: `nucleus-<name>.service`, ordered after `network-online.target`
- **Type**: `notify` (when `sdNotify = true`) or `simple`
- **Restart**: `on-failure` with 5s backoff
- **Logging**: stdout/stderr captured to journald with `SyslogIdentifier=nucleus-<name>`
- **Command**: `nucleus run --service-mode production ...` with all configured options
- **Workload identity**: Nucleus itself starts as root for setup, then drops the container workload to the configured `user` / `group` before exec
- **Hardening**: `ProtectSystem=strict`, `ProtectHome=true` at the systemd level (defense-in-depth)

### Building a Rootfs

Use `nucleus.lib.mkRootfs` to build a minimal, reproducible root filesystem:

```nix
nucleus.lib.mkRootfs {
  inherit pkgs;
  name = "my-service-rootfs";  # optional, defaults to "nucleus-rootfs"
  packages = [
    my-service-package
    pkgs.cacert       # TLS certificates
    pkgs.curl         # for health checks
    pkgs.busybox      # minimal coreutils
  ];
}
```

This produces a Nix store path containing `/bin`, `/lib`, `/etc`, etc. from the specified packages. It is mounted read-only inside the container, replacing the host bind mounts used in agent mode.

`mkRootfs` also emits a `.nucleus-rootfs-sha256` manifest at the root of the closure. Use `--verify-rootfs-attestation` or `verifyRootfsAttestation = true;` to require that manifest to match the mounted rootfs at startup.

For ephemeral provider agents, use `nucleus.lib.mkAgentToolchainRootfs`
instead. It layers a broad agent development toolchain on top of `mkRootfs`,
keeps `/bin/sh` and `/usr/bin/env` compatibility paths available, and accepts
provider CLI packages through `providerPackages`.

### Building an Image

Use `nucleus.lib.mkImage` to package a Nix rootfs plus default process config as
a reproducible Nucleus image:

```nix
let
  appRootfs = nucleus.lib.mkRootfs {
    inherit pkgs;
    name = "my-service-rootfs";
    packages = [
      my-service-package
      pkgs.cacert
      pkgs.curl
    ];
  };

  appImage = nucleus.lib.mkImage {
    inherit pkgs;
    name = "my-service-image";
    rootfs = appRootfs;
    config = {
      command = [ "/bin/my-service" "--config" "/etc/my-service.toml" ];
      env = {
        RUST_LOG = "info";
      };
      workdir = "/";
      uid = 0;
      gid = 0;
    };
  };
in
{
  services.nucleus.containers.my-service = {
    enable = true;
    image = appImage;
    command = [ ]; # use the image manifest command
    memory = "512M";
    cpus = 1.0;
  };
}
```

`mkImage` writes `manifest.json`, `rootfs.sha256`, and `store-paths` into a Nix
store output. Build-time images are cold and thin: the rootfs remains a Nix
store path, and the image manifest has no overlay diff unless it was produced by
the CLI `nucleus image commit` workflow.

## Security Notes

**Do not pass secrets via `-e` / `--env`.** Environment variables are visible in `/proc/<pid>/environ` to any process that can read it (mitigated by `hidepid=2` in production mode, but not in agent mode). Use `--secret` instead when a file works. If a provider CLI requires sensitive environment variables, use `--env-fd FD`; the fd carries a JSON object such as `{"OPENAI_API_KEY":"..."}` or a JSON array of `KEY=VALUE` strings so the values are not exposed through Nucleus argv.

**Prefer credential brokers for bearer-token APIs.** If untrusted code can drive a provider CLI, do not place the bearer token in the sandbox environment. Run a host-side broker that holds the credential, injects it into approved upstream requests, rate-limits and audits usage, and start Nucleus with `--credential-broker IP:PORT` so the sandbox can only reach that broker endpoint.

**Protect the local image signing key.** Runtime-committed image directories are verified with the host-local HMAC key selected by `NUCLEUS_IMAGE_HMAC_KEY_FILE` or the default owner-only key path. Treat that file like deployment signing material: do not share it across trust domains unless those hosts should be able to trust and produce each other's local image snapshots.

**Privilege dropping is explicit.** Nucleus must start with elevated privileges to create namespaces, mount filesystems, and configure cgroups/networking. Use `--user` / `--group` (or the NixOS module's `user` / `group` options) so the workload itself does not continue running as root after setup. In production mode, staged secrets under `/run/secrets` are re-owned to that workload identity.

**Agent mode is not hardened.** By design, agent mode applies several security mechanisms on a best-effort basis: seccomp and Landlock failures are warn-and-continue (with `--allow-degraded-security`), chroot fallback is available (with `--allow-chroot-fallback`), bridge DNS defaults to public resolvers (`8.8.8.8`), and cgroup creation failures are non-fatal. Operators requiring strict isolation for ephemeral workloads should use `--service-mode strict-agent`; operators deploying long-running NixOS services should use production mode.

## Service Modes

| Feature | Agent Mode | Strict Agent Mode | Production Mode |
|---|---|---|---|
| Service mode | `--service-mode agent` (default) | `--service-mode strict-agent` (alias: `--service-mode mitos-agent`) | `--service-mode production` |
| Degraded security | Allowed with flag | Forbidden | Forbidden |
| Chroot fallback | Allowed with flag | Forbidden | Forbidden |
| Host networking | Allowed with flag | Native `host` forbidden; `gvisor-host` allowed with gVisor + explicit opt-in | Native `host` forbidden; `gvisor-host` allowed with gVisor + explicit opt-in |
| Cgroup limits | Best-effort | Required (fatal on create/apply failure) | Required (fatal on create/apply failure) |
| Bridge DNS | Defaults to 8.8.8.8/8.8.4.4 | Must be configured explicitly | Must be configured explicitly |
| Rootfs | Host bind mounts unless `--rootfs` (optionally with `--rootfs-mode overlay`) or `--agent-toolchain-rootfs` is supplied | Host bind mounts unless `--rootfs` (optionally with `--rootfs-mode overlay`) or `--agent-toolchain-rootfs` is supplied | Pre-built Nix closure (`--rootfs`) or build-time `mkImage` image without an overlay diff |
| Workspace | Optional `/workspace`; bind/copy-in-out for agents | Optional `/workspace`; bind/copy-in-out for agents | Optional, non-executable unless read-only or policy-specific |
| Egress policy | Optional | Optional | Deny-all default where enforceable; unavailable with `gvisor-host` |
| Memory limit | Optional | Optional | Required |
| PID 1 init | Direct exec | Direct exec | Mini-init with zombie reaping + signal forwarding |
| Workload uid/gid | Root by default | User namespace remapping required when running as host root | Configurable post-setup drop via `--user` / `--group` |
| Secrets | In-memory tmpfs | In-memory tmpfs | In-memory tmpfs with volatile zeroing |
| /proc | Mounted normally | Mounted normally | `hidepid=2` (hides other processes) |
| Mount audit | Skipped | Skipped | Post-setup flag verification (fatal) |
| Seccomp trace mode | Allowed | Forbidden | Forbidden |
| Landlock ABI | Best-effort | Full enforcement required on native | V3 minimum required |
| Health checks | Optional | Optional | Optional |
| sd_notify | Optional | Optional | Optional |
| Security policies | Optional | Optional | Optional (recommended) |

## Egress Policy

When production bridge mode runs without `--egress-allow` or `--egress-domain`, Nucleus installs a strict deny-all OUTPUT policy, including DNS.
When `--egress-allow` or `--egress-domain` is specified, Nucleus applies iptables OUTPUT chain rules inside the container's network namespace:

1. Allow loopback traffic
2. Allow established/related connections
3. Allow DNS to configured resolvers
4. Resolve permitted domains to IPv4 `/32` rules at startup
5. Allow traffic to permitted CIDRs and resolved domain addresses (optionally restricted to specific ports)
6. Log denied packets (rate-limited, `nucleus-egress-denied:` prefix)
7. Drop everything else

```bash
# Allow outbound to internal network on HTTPS only
nucleus run --network bridge --dns 10.0.0.1 \
  --egress-allow 10.0.0.0/8 --egress-tcp-port 443 \
  -- ./my-service

# Allow outbound to a provider API domain on HTTPS only
nucleus run --network bridge --dns 10.0.0.1 \
  --egress-domain api.example.com --egress-tcp-port 443 \
  -- ./provider-client

# Production deny-all egress, including DNS
nucleus run --service-mode production --network bridge --dns 10.0.0.1 \
  -- ./isolated-service
```

Domain egress entries are exact DNS names, not wildcard or suffix rules. Nucleus resolves each domain with the supervisor host resolver before installing the namespace-local iptables policy, keeps only IPv4 answers, and fails startup if a domain has no IPv4 address. Long-running services that depend on provider IP rotation should restart after DNS changes, use provider-published CIDR ranges, or route traffic through a stable internal proxy and allow that proxy CIDR instead.

### Credential Broker Egress

`--credential-broker IP:PORT` is the first-class Nucleus path for bearer-token API clients that must run inside an untrusted sandbox. The actual broker process is host-side and outside Nucleus: it owns the real secret, authenticates outbound requests, enforces upstream method/path/destination limits, and writes the audit log. Nucleus enforces the sandbox side by installing a deny-by-default policy that allows only TCP to the broker `/32` and disables DNS from the sandbox.

```bash
# Broker listens on the host side of the bridge, for example 10.0.42.1:8080.
# Nucleus injects HTTP_PROXY/HTTPS_PROXY values pointing at that endpoint.
nucleus run --network bridge --credential-broker 10.0.42.1:8080 \
  -- ./provider-client

# If the provider uses a base URL setting instead of proxy variables:
nucleus run --network bridge --credential-broker 10.0.42.1:8080 \
  --credential-broker-no-proxy-env \
  -e PROVIDER_BASE_URL=http://10.0.42.1:8080 \
  -- ./provider-client
```

Broker mode is mutually exclusive with `--egress-allow`, `--egress-domain`, `--egress-tcp-port`, and `--egress-udp-port`; adding direct routes would defeat the broker boundary. The broker endpoint must be an IPv4 bridge address, not `127.0.0.1`, because loopback is local to the container namespace.

## Native Bridge Backends

For the native runtime, `--network bridge` now has two backends:

| `--nat-backend` | When used | Implementation |
|---|---|---|
| `auto` | Default | Kernel bridge/veth/iptables when privileged, `slirp4netns` userspace NAT when rootless |
| `kernel` | Explicit opt-in | Kernel bridge + veth + iptables MASQUERADE/DNAT |
| `userspace` | Explicit opt-in | `slirp4netns` userspace NAT + API-socket port forwarding |

This changes the native rootless behavior from "degrade to `none`" to a real userspace NAT path.

## gVisor Network Modes

When using gVisor (`--runtime gvisor`), the network mode is selected explicitly:

| Container `--network` | gVisor `--network` flag | Description |
|---|---|---|
| `none` | `none` | Fully isolated (default for agents) |
| `bridge` | `host` | Nucleus prepares a bridge/userspace NAT namespace, then runsc inherits it |
| `gvisor-host` | `host` | gVisor hostinet mode; omits the OCI network namespace and requires `--allow-host-network` |

The `gvisor-host` mode is intentionally separate from native `host` networking. Native `host` remains a direct host namespace mode. `gvisor-host` keeps the gVisor runtime boundary, but weakens network isolation by letting runsc hostinet use the host network stack. Because there is no Nucleus-owned network namespace in this mode, Nucleus egress policy is unavailable with `gvisor-host`.

## Terminal And Console Sockets

`--terminal` runs the workload behind a pseudoterminal. Supplying
`--console-socket <path>` implies terminal mode and follows the OCI console
socket convention: the runtime connects to the AF_UNIX socket and sends the PTY
master file descriptor with `SCM_RIGHTS`.

Native containers allocate the PTY directly. The workload process becomes a
session leader, the PTY slave becomes its controlling TTY, and stdin/stdout/stderr
all point at that slave. gVisor containers set `process.terminal = true` and
`process.consoleSize` in the generated OCI config, then pass `--console-socket`
through to `runsc`.

Console bytes are not decoded or rewritten by Nucleus. Clients such as
mitos/libghostty are expected to parse and render the raw stream. Window resizing
uses PTY window-size ioctls; foreground SIGWINCH is also forwarded to the
container process.

## OCI Support

Nucleus is not a generic external OCI runtime. For gVisor execution it generates an OCI bundle layout and `config.json` that follow the OCI runtime-spec fields Nucleus uses in practice.

- `process`: args, env, cwd, `noNewPrivileges`, terminal settings, rlimits, and `process.user` (`uid`, `gid`, `additionalGids`)
- `root` and `mounts`: read-only rootfs plus bind, tmpfs, and secret mounts
- `linux`: namespaces, cgroup path, resource limits, uid/gid mappings, masked paths, readonly paths, devices, seccomp, and sysctls
- `hooks`: OCI lifecycle hooks with OCI state JSON on stdin
- `annotations`: runtime metadata passed through to the bundle

That OCI path is the contract used with `runsc`. The native runtime uses Nucleus's direct Linux setup path rather than exposing a separate OCI CLI surface.

Lifecycle hooks execute host-side commands with supervisor privileges. They are not accepted in topology service definitions; use only explicit administrative `nucleus create --hooks` configuration for hooks.

## Machine-Readable Events

Use `--events-jsonl <path>` to write control-plane lifecycle events as JSON Lines, or `--events-fd <fd>` to write them to an inherited file descriptor. The stream is separate from workload stdout/stderr and PTY bytes; operators can consume it without parsing user process output. `--events-fd` rejects stdio descriptors and is not available with `--detach`; use `--events-jsonl` for detached containers.

Events include a container start record and a final summary record. The records carry the container ID, PID, cgroup path, workspace/context mount, network mode, seccomp mode, Landlock status, capability status, resource limits, exit status, resource stats, and whether cleanup succeeded.

## Additional Hardening Flags

- `--seccomp-profile <path>` loads a custom per-service seccomp profile (OCI JSON format).
- `--seccomp-profile-sha256 <hex>` verifies the profile's SHA-256 hash before loading.
- `--seccomp-mode trace|enforce` switches between trace (record all syscalls) and enforce (default).
- `--seccomp-log <path>` writes NDJSON syscall trace when in trace mode.
- `--caps-policy <path>` loads a TOML capability policy (replaces default drop-all).
- `--caps-policy-sha256 <hex>` verifies the capability policy hash.
- `--landlock-policy <path>` loads a TOML Landlock filesystem policy (replaces default rules).
- `--landlock-policy-sha256 <hex>` verifies the Landlock policy hash.
- `--verify-context-integrity` hashes the source context tree before launch and verifies the populated `/context` tree matches.
- `--verify-rootfs-attestation` requires a `.nucleus-rootfs-sha256` manifest and verifies the mounted rootfs against it.
- `--seccomp-log-denied` requests kernel logging for denied seccomp decisions when the host supports `SECCOMP_FILTER_FLAG_LOG`.
- `--require-kernel-lockdown integrity|confidentiality` refuses startup unless `/sys/kernel/security/lockdown` satisfies the requested mode.
- `--gvisor-platform systrap|kvm|ptrace` selects the runsc backend explicitly.
- `--time-namespace` enables Linux time namespaces for native containers.
- `--disable-cgroup-namespace` turns off cgroup namespace isolation when a workload needs the host cgroup view.

If `NUCLEUS_OTLP_ENDPOINT` or `OTEL_EXPORTER_OTLP_ENDPOINT` is set, Nucleus exports lifecycle spans over OTLP in addition to normal local logging.

## Development

This project uses Nix flakes for reproducible builds:

```bash
# Enter development shell
nix develop

# Build
cargo build

# Run tests
cargo test

# Run with Apalache installed (for TLA+ trace replay)
cargo test -- --include-ignored

# Build release binary
cargo build --release

# Clippy
cargo clippy --all-targets -- --deny warnings

# Host vs container runtime benchmarks (requires root)
sudo -E cargo bench --bench container_runtime
```

### Project Structure

```
nucleus/
├── src/
│   ├── container/      # Container orchestration, lifecycle, state, config
│   ├── isolation/      # Namespace management, user mapping, attach
│   ├── resources/      # cgroup v2 resource control, stats
│   ├── filesystem/     # tmpfs, rootfs mounting, context population, secrets, attestation
│   ├── image/          # Local signed image manifests, diff export/import, verification
│   ├── security/       # Capabilities, seccomp, Landlock, gVisor, OCI, policy files
│   │   ├── caps_policy.rs       # TOML capability policy loader
│   │   ├── landlock_policy.rs   # TOML Landlock policy loader
│   │   ├── seccomp_trace.rs     # Seccomp trace mode (syscall recording)
│   │   ├── seccomp_generate.rs  # Profile generator from traces
│   │   └── policy.rs            # Shared policy infrastructure (SHA-256, TOML/JSON loaders)
│   ├── network/        # Networking (none/host/bridge), egress policy
│   ├── topology/       # Multi-container topology (Compose equivalent)
│   │   ├── config.rs   # TOML topology config (services, networks, volumes)
│   │   ├── dag.rs      # Dependency DAG with topological sort
│   │   ├── reconcile.rs # Diff running vs desired state, apply changes
│   │   └── dns.rs      # Per-topology /etc/hosts DNS
│   ├── checkpoint/     # CRIU checkpoint/restore
│   ├── audit.rs        # Structured audit log (JSON events)
│   └── error.rs        # Error types
├── nix/
│   └── module.nix      # NixOS module (containers + topologies)
├── config/             # Security policy files (per-service)
│   ├── *.seccomp.json  # Seccomp syscall allowlists (OCI format)
│   ├── *.caps.toml     # Capability bounding set policies
│   └── *.landlock.toml # Landlock filesystem access rules
├── tests/
│   ├── model_based_*   # Property-based tests from TLA+ specs
│   └── tla_*           # tla-connect driver tests
├── formal/tla/         # TLA+ formal specifications
├── intent/             # Intent high-level specs
└── flake.nix           # Nix flake (packages, modules, lib.mkRootfs, lib.mkImage)
```

### Testing

Nucleus uses spec-driven development with comprehensive testing:

- **Unit tests**: Individual component functionality
- **Model-based tests**: Property-based tests verifying TLA+ specifications
- **tla-connect tests**: TLA+ to Rust state machine mapping
- **Integration tests**: Complete container lifecycle

All state machines are formally verified using TLA+ and the Apalache model checker.

### Performance Benchmarks

`benches/container_runtime.rs` compares the same workloads when run directly on the host vs inside a native Nucleus container. The matrix covers:

- cold startup (`/bin/sh -lc ':'`)
- a CPU-bound shell arithmetic loop
- context-heavy file scans with both bind-mounted and copied context
- a constrained profile that applies the same cgroup limits to the direct host process and the containerized process

Because the benchmark creates namespaces and cgroups, it must run as root:

```bash
sudo -E cargo bench --bench container_runtime
```

Criterion writes the comparison reports to `target/criterion/container_runtime/`.

### System-Level TLA+ Model

A composed system model verifies cross-subsystem ordering, authorization, and end-to-end progress:

```bash
apalache-mc check --config=formal/tla/Nucleus_System.cfg formal/tla/Nucleus_System.tla
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
