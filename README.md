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

### PostgreSQL 18 (pgbench, 8 clients, 30s, scale 50, 3 runs)

The native runtime stays within run-to-run noise of bare metal, while the gVisor
runtime pays a consistent ~62% tax from the Sentry's per-syscall user-space
emulation. Occasional wins over bare metal should be treated as benchmark
noise rather than a guaranteed speedup.

**SELECT-only (read-heavy)**

| Environment | I/O Method | Avg TPS | Avg Latency | vs Baremetal |
|---|---|---|---|---|
| Baremetal | worker | 170,411 | 0.047 ms | baseline |
| Baremetal | io_uring | 174,026 | 0.046 ms | +2.1% |
| **Nucleus** | **worker** | **169,577** | **0.047 ms** | **−0.5%** |
| **Nucleus** | **io_uring** | **172,482** | **0.046 ms** | **+1.2%** |
| gVisor | worker | 65,683 | 0.122 ms | −61.5% |

**TPC-B (mixed read/write)**

| Environment | I/O Method | Avg TPS | Avg Latency | vs Baremetal |
|---|---|---|---|---|
| Baremetal | worker | 4,341 | 1.845 ms | baseline |
| Baremetal | io_uring | 4,516 | 1.772 ms | +4.0% |
| **Nucleus** | **worker** | **4,583** | **1.746 ms** | **+5.6%** |
| **Nucleus** | **io_uring** | **4,607** | **1.736 ms** | **+6.1%** |
| gVisor | worker | 1,655 | 4.834 ms | −61.9% |

> Measured on Linux 6.18 x86_64 with PostgreSQL 18.4. All three environments run
> **fully unprivileged** (Nucleus rootless with `--userns keep-id`, no `sudo`);
> the harness bind-mounts a host `pgdata` and uses host networking, so it
> measures the steady-state cost of each isolation layer rather than image
> unpacking or cold start. gVisor's Sentry does not implement `io_uring`, so it
> is measured with `io_method=worker` only. Full results:
> [`benches/pg18_io/results/`](benches/pg18_io/results/)
>
> Run it yourself (rootless):
> ```bash
> nix shell nixpkgs#postgresql_18 -c \
>   env ROOTLESS=1 SCALE=50 CLIENTS=8 DURATION=30 RUNS=3 \
>   bash benches/pg18_io/bench.sh
> ```
> Add `GVISOR_PLATFORM=systrap` if `/dev/kvm` is unavailable, or `SKIP_GVISOR=1`
> to measure baremetal + native only.

## Why Nucleus?

- **Declarative by default for services** – Production deployments are defined in NixOS and TOML rather than stitched together with ad hoc runtime scripting
- **Deep Nix integration** – First-class NixOS module, `mkRootfs`, `mkImage`, and Nix store closures for minimal, locked-down service roots
- **Reproducible service builds** – Flake-based packaging, pinned inputs, rootfs attestation, and image signatures make runtime state auditable and repeatable
- **Zero-overhead isolation** – Direct use of cgroups, namespaces, pivot_root, capabilities, seccomp, and Landlock
- **Memory-backed filesystems** – Container disk mapped to tmpfs, pre-populated with agent context
- **gVisor integration** – Optional application kernel for enhanced security, including networked service mode
- **OCI runtime-spec subset for gVisor** – Generates OCI bundle/config data for `runsc`, including process identity, mounts, namespaces, seccomp, and cgroup path wiring
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
| Default egress | Allow-all outbound | Deny-by-default; allow per CIDR/domain via namespace nftables |
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
- **Landlock** – Native filesystem and TCP access rules, with abstract Unix socket and signal scoping on Landlock ABI 6 (Linux 6.12+)
- **gVisor** – Optional application kernel (runsc) with none, bridge handoff, and explicit gvisor-host network modes
- **OCI bundle generation** – Emits OCI `config.json` plus bundle layout for gVisor, including `process.user`, seccomp, resource limits, and namespace mappings
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

- **GPU passthrough** – `--gpu auto|nvidia|amd|intel|all` binds host GPU device nodes into `/dev`, installs a cgroup v2 device allowlist (`BPF_PROG_TYPE_CGROUP_DEVICE`), relaxes the seccomp `ioctl` filter for vendor driver ioctls, and bind-mounts driver support files. Explicit device selection, NVIDIA env vars, and a programmatic `gpu` config document field are supported. See [spec/gpu-passthrough.md](spec/gpu-passthrough.md).
- **Local signed image snapshots** – Native overlay-backed containers can be committed, verified, inspected, loaded, and run as thin image directories over a Nix rootfs base.
- **Privilege drop for services** – `--user`, `--group`, and `--additional-group` now apply a real post-setup workload identity in both the native runtime and gVisor.
- **Ownership-aware secrets and writable paths** – Production secret staging and NixOS `createHostPath = true` defaults now align file ownership with the configured workload user/group.
- **OCI bundle identity support** – Generated gVisor OCI configs now carry `process.user` including supplementary groups, alongside namespaces, mounts, resource limits, seccomp, and `cgroupsPath`.
- **Probe execution under workload identity** – Exec-based health and readiness probes now run as the configured service account instead of implicitly as root.
- **Systemd/NixOS service integration improvements** – The module exposes `user`, `group`, and `supplementaryGroups`, and packaged Nix usage includes `gvisor` in the flake/dev shell path.

## Usage

### Agent Mode (default)

```bash
# Run agent in isolated container with pre-populated context
nucleus run --context ./agent-context/ -- /usr/bin/agent

# Specify resource limits. A workload that exceeds --memory is OOM-killed
# (swap is off). --memory-high SIZE adds a throttling watermark below it.
nucleus run --memory 512M --cpus 2 --context ./ctx/ -- ./agent

# Name your container
nucleus run --name my-agent --context ./ctx/ -- ./agent

# Use gVisor for enhanced isolation
nucleus run --runtime gvisor --context ./ctx/ -- ./agent

# Rootless mode
nucleus run --rootless -- /bin/sh

# Rootless system services (e.g. PostgreSQL) that refuse euid 0:
# --userns keep-id maps your uid to itself so host-owned bind mounts just work
# (requires /etc/subuid + /etc/subgid, exactly like Docker/Podman rootless).
nucleus create --userns keep-id --user "$(id -u)" --group "$(id -g)" \
  -v ./pgdata:/pgdata -- postgres -D /pgdata
# --user <non-zero> alone auto-selects keep-id when /etc/subuid is configured.
# --userns auto     Podman/Docker default (workload uid in the subuid range)
# --userns nomap    historic (only container root usable)
# --uidmap/--gidmap explicit container:host:size mappings (Podman syntax)

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

### Embedding in an Orchestrator

An orchestrator that launches Nucleus per task, reads the workload's stdio as
data and may be killed at any time needs a few guarantees beyond a plain CLI
run.

**Clean stdio.** `--quiet` keeps Nucleus off the workload's streams: the
container ID is not printed on stdout, and stderr logging defaults to errors.
`--events-fd` and `create --config-fd` imply it. The ID is reported in the
`container_started` and `container_summary` events; with `--config-fd` and no
event stream it is still printed, since nothing else would carry it. `RUST_LOG`
and `--log <file>` keep full logging available.

```bash
nucleus --events-fd 5 run --config-fd 4 4<request.json 5>events.jsonl
```

**Held start.** `--start-fd FD` (launch config `start_fd`) gives `run` the
create → verify → start split of OCI `create`/`start` without a second
process or persisted state. After all setup is complete — namespaces, mounts,
cgroup, dropped capabilities, seccomp, Landlock — Nucleus emits
`container_started` and the container's init blocks reading one byte from the
inherited descriptor, exactly like the OCI exec FIFO. The workload is exec'd
only when the byte arrives, so an orchestrator can verify the reported
posture (security status, limits, cgroup, mounts) before the workload's first
instruction. If the descriptor reaches EOF instead, Nucleus tears the
container down and exits non-zero without running the workload; the
`container_summary` event carries a `Start gate closed` error. A `SIGTERM`
to the supervisor while the workload is held cancels the hold and tears the
container down the same way (exit status 143). The gate must not share a
descriptor with `--events-fd` and is not available with `--detach`. With
`--config-fd` the gate belongs in the launch document (`"start_fd": 4`),
since the document owns the whole request:

```bash
mkfifo gate
exec 9<>gate   # holder: a writer now exists, so the read-only open returns
exec 4<gate    # the read-only end Nucleus inherits (9 is rw; it would never EOF)
nucleus --events-fd 5 run --config-fd 3 \
  3<request.json 5>events.jsonl 4<&4 9>&- &
# ... read container_started from events.jsonl, verify the posture ...
printf go >&9                     # release the workload
# refuse instead with: exec 9>&-  (EOF, no byte)
```

The gate descriptor should be a read-only pipe end (or an equivalent
one-byte readable descriptor); it must be greater than 2 and is inherited by
the container's init, which closes it before exec'ing the workload. A
descriptor that also carries a write end into Nucleus (an `<>` open) can
never reach EOF, so refusals would hang — keep the writer only on the
orchestrator side.

**No orphans.** The container dies with its supervisor. Every setup process
arms a parent-death signal, so killing only the `nucleus` process (SIGKILL, OOM)
takes the container's init, and with it the PID namespace or the gVisor
sandbox, down too. When the container has a cgroup, a small detached reaper
kills and removes that cgroup once the supervisor is gone. `SIGTERM`, in
contrast, is forwarded to the container's init (the workload, or the
production mini-init) so it can shut down gracefully; as with any OCI
runtime, a workload that is PID 1 of its PID namespace and installs no
handler ignores it — use `SIGKILL` (or `nucleus stop`/`nucleus kill`) for a
guaranteed teardown.

**Caller-owned volumes.** `--volume` refuses every source under `/home`, `/tmp`,
`/run` and `/var/lib`. Add the `caller-owned` option to mount a directory you
own there, such as a per-attempt directory:

```bash
nucleus run --volume /var/lib/mitos/attempts/42:/attempt:rw,caller-owned -- ./agent
```

The directory must be owned by the calling user and not world-writable. Whole
home and runtime directories (`/home/alice`, `/run/user/1000`), the shared
parents themselves, system trees such as `/etc` and `/proc`, and Nucleus' own
state stay refused.

**Brokered egress without a network.** `--broker-socket PATH` gives a workload
one way out: a host unix socket behind which a host-side broker owns policy,
credentials and auditing. It requires `--network none`, works rootless, and
is native-runtime only (see below). The container keeps its private network
namespace with loopback as the only interface, and IP sockets are allowed.

With `--broker-proxy-listen 127.0.0.1:PORT` Nucleus runs the forwarder
itself: the workload connects to that loopback address with TCP, and the
supervisor relays each connection to the broker socket. The socket is not
mounted into the container, the workload needs no forwarder binary, and
`HTTPS_PROXY`/`HTTP_PROXY` (and lower-case forms) point at the listener
unless you set them yourself or pass `--no-broker-proxy-env`. The
`container_started` event reports the address as
`container.broker_proxy_listen`.

```bash
nucleus run --runtime native --trust-level trusted \
  --broker-socket /run/mitos/relay.sock \
  --broker-proxy-listen 127.0.0.1:3128 -- ./agent
```

Without `--broker-proxy-listen`, the socket is mounted read-only at
`/run/nucleus/broker.sock` (named in `NUCLEUS_BROKER_SOCKET`) and the workload
runs its own forwarder on loopback.

The socket must be owned by the calling user. In both forms Landlock (kernel
ABI 9 or later) refuses connections to every other pathname unix socket, such
as one inside a mounted volume; on older kernels only the mount namespace
limits them. gVisor is refused: runsc can only reach a mounted host socket
with `--host-uds=open`, which opens every host socket visible in the sandbox,
not just the broker. Untrusted workloads, which require gVisor, therefore need
`--trust-level trusted --runtime native` to use the broker.

**Resource limits without root.** Container cgroups are created in the subtree
delegated to the caller when there is one, so strict modes work for an
unprivileged service:

```ini
# mitos.service
[Service]
User=mitos
Delegate=cpu io memory pids
DelegateSubgroup=supervisor
```

Nucleus recognises a `Delegate=` unit when it runs in that unit's cgroup or in
a direct child of it (`DelegateSubgroup=`), and enables the controllers it
needs there. For system units it reads the delegation marker the system manager
sets. systemd's user manager sets no marker, so for a service or scope under
`user@<uid>.service` Nucleus asks the user manager
(`systemctl --user show -p Delegate`); this works for
`systemd-run --user [--scope] -p Delegate=yes` and user services with
`Delegate=yes`. A delegated cgroup that still has member processes cannot hand
controllers to its children: keep the orchestrator in a subgroup. A lone
`nucleus` moves itself into a `nucleus-supervisor` leaf.

Other layouts are not guessed, and neither is a user-manager unit when
`systemctl --user` cannot reach the manager (for example without
`XDG_RUNTIME_DIR` or the user bus). In those cases name the delegated subtree
with `NUCLEUS_CGROUP_ROOT`:

```bash
systemd-run --user --scope -p Delegate=yes sh -c \
  'NUCLEUS_CGROUP_ROOT=/sys/fs/cgroup$(sed -n "s/^0:://p" /proc/self/cgroup) \
   exec nucleus run --strict-agent --memory 256M -- ./agent'
```

Without root or a delegated subtree, strict modes fail rather than run
unlimited, and the error points to `Delegate=` and `NUCLEUS_CGROUP_ROOT`. The effective cgroup is reported as `container.cgroup_path` in the
event stream.

### Workspace

`--workspace <host-path>` mounts the host project tree at `/workspace`. The
process cwd defaults to `/workspace` via `--workdir /workspace`.

`--workspace-mode` accepts:

| Mode | Behavior |
|---|---|
| `bind-rw` | Bind mount the host path read-write at `/workspace` (default). |
| `bind-ro` | Bind mount the host path read-only at `/workspace`. |
| `copy-in-out` | Copy the host path into a private staging directory, run against that staged tree, then sync changes back after exit. Both directions strip set-user-ID and set-group-ID bits. |

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
`/usr`, `/lib`, or `/nix/store` binds by passing a pinned agent toolchain rootfs:

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

### GPU Passthrough

Expose host GPUs to a container for CUDA, ROCm, or Mesa/Vulkan compute workloads.
GPU access is an explicit, audited privilege grant — Nucleus preserves its
full defense-in-depth stack (namespaces, capabilities, Landlock, cgroups)
while binding only the requested device nodes and relaxing only the `ioctl`
seccomp rule.

```bash
# Auto-detect and bind whatever GPU is present on the host
nucleus create --gpu auto --rootfs /nix/.../cuda-rootfs -- python train.py

# Pin a vendor and explicit devices (overrides discovery)
nucleus create --gpu nvidia \
  --gpu-device /dev/nvidia0 \
  --gpu-device /dev/nvidiactl \
  --rootfs /nix/.../cuda-rootfs -- nvidia-smi

# AMD ROCm
nucleus create --gpu amd --rootfs /nix/.../rocm-rootfs -- rocminfo

# Bind only the devices; the rootfs ships its own driver stack
nucleus create --gpu auto --no-gpu-driver-libs --rootfs /nix/.../rootfs -- ./workload
```

What happens when `--gpu` is set:

- **Device nodes** — the resolved `/dev/nvidia*`, `/dev/dri/renderD*`, `/dev/kfd`,
  `/dev/nvidia-uvm*`, etc. are recreated in the container `/dev` at their host
  paths, using the same device numbers and workload UID/GID with mode `0660`.
  Host device ownership and permissions remain unchanged. Native setup requires
  permission to create device nodes and fails if this is unavailable.
- **cgroup device allowlist** — a `BPF_PROG_TYPE_CGROUP_DEVICE` program is
  attached to the container cgroup, allow-listing only the base `/dev` nodes
  plus the bound GPU devices. If the cgroup or filter is unavailable, GPU
  setup fails unless the caller explicitly sets `--allow-degraded-security`.
- **Seccomp** — the restrictive terminal-only `ioctl` rule is replaced with an
  unconditional allow, since vendor driver ioctl request codes cannot be
  enumerated. All other seccomp restrictions remain.
- **Driver support files** — The runtime binds individual NVIDIA driver
  libraries and vendor manifests read-only. Intel discovery selects DRM render
  nodes. Explicit rootfs images supply their own driver stack.
- **Environment** — `NVIDIA_VISIBLE_DEVICES`, `NVIDIA_DRIVER_CAPABILITIES`, and
  the EGL vendor manifest pointer are injected at exec time.
- **gVisor** — runsc receives OCI `linux.devices` entries (major/minor/type) so
  it creates the device nodes and installs the matching cgroup rules inside its
  sandbox, plus bind mounts for the driver support files.
- **Auditing** — the `container_started` event stream reports the vendor,
  visible devices, driver capabilities, and the relaxed-seccomp flag.

CLI flags:

| Flag | Purpose |
|---|---|
| `--gpu <auto\|nvidia\|amd\|intel\|all>` | Enable GPU passthrough and select vendor(s) |
| `--gpu-device <path>` | Explicit device node (repeatable; overrides discovery) |
| `--gpu-driver-capabilities <s>` | `NVIDIA_DRIVER_CAPABILITIES` (default `compute,utility`) |
| `--gpu-visible-devices <s>` | `NVIDIA_VISIBLE_DEVICES` (default `all`) |
| `--no-gpu-driver-libs` | Do not bind host driver userspace libraries |

`--gpu` is rejected in `--service-mode production` (declare GPU needs through an
attested rootfs instead). The same configuration is available programmatically
via the `gpu` field of the launch config document (`--config`/`--config-fd`).

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
nucleus image commit worker -o ./worker.nucleus-image --freeze

# Verify/load and inspect the image
nucleus image load ./worker.nucleus-image
nucleus image inspect ./worker.nucleus-image

# Run the manifest command, or override it after --
nucleus image run ./worker.nucleus-image -- /bin/cat /tmp/result
```

`nucleus image commit` requires a container launched with `--rootfs-mode
overlay`; overlay rootfs mode is currently native-runtime only and production
mode rejects it.
Each runtime commit signs the image with Ed25519. The first commit creates a
32-byte private seed and its 32-byte public key. The default seed is
`/var/lib/nucleus/image-ed25519.key` for root and
`$XDG_DATA_HOME/nucleus/image-ed25519.key` for other users
(`XDG_DATA_HOME` defaults to `~/.local/share`).

To verify on another host, provision the companion `.pub` file through a
trusted channel and transfer the image preserving numeric ownership, modes,
nanosecond mtimes and xattrs. For example, these commands use an explicit
signing seed on the producer and a provisioned public key on the verifier.

```sh
nucleus image commit worker -o ./worker.nucleus-image --image-key-file /var/lib/nucleus/release.key
nucleus image load ./worker.nucleus-image --image-key-file /etc/nucleus/release.key.pub
```

`NUCLEUS_IMAGE_SIGNING_KEY_FILE` selects the commit key.
`NUCLEUS_IMAGE_VERIFY_KEY_FILE` selects the public key for load, inspect and run.
By default verification reads the companion `.pub` file beside the selected
signing-key path. Recommit legacy HMAC images from their trusted source before upgrading consumers.
Nix-built images from `nucleus.lib.mkImage` live in `/nix/store` and omit
`image.sig` because Nix store/substituter trust is the integrity root.

Runtime commits record the original command, explicit environment variables,
workdir, uid/gid, supplementary groups, and an overlay diff. The diff exporter
preserves uid/gid, mode bits, mtimes, symlinks, xattrs, POSIX ACL xattrs, and
Linux file-capability xattrs; commit fails if the caller cannot preserve
metadata. Local image signatures cover both content and preserved metadata.

`nucleus image commit` reads the container's live overlay upperdir. Use
`--freeze` to freeze the recorded cgroup while the diff is copied; without it,
concurrent writes can be captured in a torn state. Freezing requires the
container to have a recorded cgroup path. Runtime-committed images are a
development/CLI workflow: the NixOS production module consumes build-time
`mkImage` images only and intentionally rejects images with overlay diffs. Image
run also constrains `base.rootfs_path` to a canonical `/nix/store` rootfs before
mounting it as the overlay lowerdir.

Image v2 is a single-rootfs plus optional single-diff directory format. There is
no layer chain, image store, registry push/pull, or `ls/rm/cp` image management
surface; operators manage image directories directly or use Nix store paths for
declarative production deployments.

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
  --egress-dns --egress-domain api.example.com \
  --egress-tcp-port 443 --egress-tcp-port 8443 \
  --health-cmd "curl -sf http://localhost:8080/health" \
  --health-interval 30 --health-retries 3 \
  --secret /run/secrets/tls-cert:/run/secrets/tls-cert \
  --systemd-credential db-url:/run/secrets/db-url \
  --volume /srv/myservice:/var/lib/myservice:rw \
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

#### Nested sandboxes

Workloads cannot create namespaces under either runtime, so tools that sandbox
their own subprocesses with namespaces (bubblewrap, `unshare`, the Codex CLI
tool sandbox) do not work inside a container. The native runtime refuses
`unshare`, `setns`, and `clone` with namespace flags with `EPERM`; gVisor
refuses the user-namespace ID mapping. Disable the harness's own sandbox (for
example Codex `--sandbox danger-full-access`) and rely on Nucleus as the single
enforcing layer.

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

The native enforcing filter permits ordinary futex waits, wakes and requeues. Mutexes configured with `PTHREAD_PRIO_INHERIT` require futex operations that this filter blocks. Unix-domain sockets and socket pairs are available in every network mode. Enabling networking also permits IPv4 and IPv6 TCP streams and UDP datagrams, with either the default or explicit protocol. The filter blocks `setsockopt(IPPROTO_TCP, TCP_ULP)`.

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
min_abi = 6

[tcp]
bind = [8080]
connect = [443]

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

Native seccomp rejects simultaneous write and execute permissions in `mmap`, `mprotect`, and `pkey_mprotect` requests, and rejects every executable `shmat` attachment. A mapping can still be written first and made executable afterwards, so this is an exploit mitigation and does not stop a workload from introducing native code. W^X violations return `ENOMEM` instead of killing the process: V8-based runtimes (Node ≥ 26, Electron, Chromium) `mprotect` their entire 512 MB code range RWX during startup and fatal on every other outcome, so they are run with `--seccomp-allow mmap --seccomp-allow mprotect`, which lifts the W^X mask for exactly the named syscalls (logged with a warning at startup). Seccomp returns `EPERM` for `PR_SET_MM`. The built-in policy requires explicit `--seccomp-allow` entries for `splice`, `tee`, and `sendfile` in every network mode; without them these calls return `ENOSYS` so callers fall back to `read` and `write`. The `io_uring` family behaves the same way: libuv (Node ≥ 26) probes it once per event loop and falls back to its thread pool on `ENOSYS`, while real io_uring users (for example PostgreSQL 18+ with `io_method=io_uring`) opt in with `--seccomp-allow`. GPU mode still blocks `TIOCSTI`, `TIOCLINUX`, and the legacy console keyboard and virtual terminal requests (`0x4Bxx`, `0x56xx`) on all file descriptors.

`--seccomp-allow mknod`, `mknodat`, and `kcmp` are argument-filtered: node creation is limited to FIFOs, sockets, and regular files, and `kcmp` to file-description comparison. Native seccomp profiles cannot allow `unshare`, `setns`, `mount_setattr`, `memfd_create`, `memfd_secret`, `ptrace`, `process_vm_writev`, `pidfd_getfd`, `open_by_handle_at`, `syslog`, or the clock setters.

Native containers keep procfs `nosuid,nodev,noexec` and verify every proc mount before handoff. Execution through descriptor links is blocked where it is decided: `execveat(AT_EMPTY_PATH)` is denied by seccomp, Landlock's execute allowlist is evaluated against the link target, and `MNT_NOEXEC` follows the resolved file's own mount — `/tmp` is mounted `noexec` (like the sandbox home and `/dev/shm`), so files there can be neither executed nor mapped `PROT_EXEC`. `/proc/self`, `/proc/thread-self` and `/dev/fd/N` resolve normally again; the earlier mount-wide `nosymfollow` flag broke them with `ELOOP`. In network modes `setsockopt` is allowed only at well-known socket-option levels (`UDP_ENCAP` and `TCP_ULP` are denied) and `MSG_OOB` is filtered from the send/recv flags. Recreate running containers to pick up the new mounts and saved seccomp program.

Native `--network none` denies all TCP binds and connects. With bridge or explicitly enabled host networking, omitting a direction leaves it to the existing network policy. An empty list denies that direction, and bind port `0` permits ephemeral port allocation. Explicit port restrictions require enforcement. The rules apply to IPv4 and IPv6 TCP.

Native workloads and their descendants can use abstract Unix sockets and send signals within their Landlock domain. Use a pathname notification socket for communication with a host service manager. An attach command receives the launch ruleset and enters a separate domain, which also limits its IPC with the original workload. Production checks write and execute grants for overlap after resolving the rule paths inside the container. In custom policies, executable directories and files need an explicit `execute` grant.

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
path = "/srv/nucleus/myapp/db"
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

      # This service uses native policies and configures a host bridge.
      privilegedSupervisor = true;
      runtime = "native";
      trustLevel = "trusted";
      network = "bridge";
      natBackend = "auto";  # or "userspace" to force slirp4netns
      dns = [ "10.0.0.1" ];  # internal resolver – no public DNS default
      portForwards = [ "127.0.0.1:8080:8080" "127.0.0.1:8443:8443" ];

      # Egress policy – audited outbound access
      egressAllow = [ "10.0.0.0/8" ];
      egressDns = true;
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

      # Provision a private JSON object of environment variables at runtime.
      environmentFile = "/run/secrets/proxy-env.json";

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
- Each supervisor runs under a per-unit dynamic user by default. Set `privilegedSupervisor = true` for operations requiring host privileges. The workload identity is configured separately through `user` and `group`.
- Containers default to untrusted gVisor workloads with networking disabled. Both unit types bound capabilities, filter system calls, restrict namespaces and use a delegated cgroup subtree. State is under `/run/<unit-name>/state`.

When upgrading, move inline NixOS `environment` values into a private runtime JSON file and set `environmentFile`. Supply secret and credential sources as quoted absolute host paths. Replace `extraArgs` with typed module options. For writable topology volumes, add their host directories to `writablePaths`. Use a quoted runtime `configFile` path for topology TOML containing sensitive values and grant the supervisor read access.

Compose records topology ownership at launch. Before the first reconcile after upgrading, stop legacy containers by ID if their names conflict with the desired services. Topology services default to gVisor. Set `runtime = "native"` explicitly for trusted services that require native features such as exec health checks or filtered bridge networking. Encrypted topology networks are currently rejected during validation.

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

`mkRootfs` also emits a `.nucleus-rootfs-sha256` manifest at the root of the closure. Use `--verify-rootfs-attestation` or `verifyRootfsAttestation = true;` to verify the registered NAR hashes of the selected rootfs and its declared store objects against the host Nix database before launch. Verification also checks canonical store modes, root ownership and the embedded content manifest. It requires the host Nix daemon and a registered store rootfs.

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

**Do not pass secrets via `-e` / `--env`.** Environment variables are visible in `/proc/<pid>/environ` to any process that can read it. Use `--secret` instead when a file works. If a provider CLI requires sensitive environment variables, use `--env-fd FD`; the fd carries a JSON object such as `{"OPENAI_API_KEY":"..."}` or a JSON array of `KEY=VALUE` strings so the values are not exposed through Nucleus argv.

**Prefer credential brokers for bearer-token APIs.** If untrusted code can drive a provider CLI, do not place the bearer token in the sandbox environment. Run a host-side broker that holds the credential, injects it into approved upstream requests, rate-limits and audits usage, and start Nucleus with `--credential-broker IP:PORT` so the sandbox can only reach that broker endpoint. Proxy environment variables are client hints, not the security boundary: Nucleus enforces the boundary with namespace-local egress rules, and non-HTTP clients that ignore proxy variables are denied unless they speak to the broker endpoint.

**Protect the image signing key.** Keep the private seed on the signing host. Distribute only its public key to hosts that load, inspect, or run the images.

**Workload identity.** When host root launches a default agent, Nucleus reserves a separate block of 65,536 host UIDs and GIDs for each launch. Container root maps to the first ID in that block. Nucleus excludes ranges delegated in `/etc/subuid` and `/etc/subgid` and IDs listed in the local password and group files. Automatic allocation requires readable policy files and file-based subordinate ID delegation. Host bind mounts use the mapped identity for permission checks. To run an agent with an existing unprivileged host identity, pass its nonzero `--user` and `--group`. With `--workspace-mode copy-in-out`, the workload edits a private copy owned by its mapped identity.

Reservations live in `/var/lib/nucleus/userns-ranges` across all `--root` directories. The pool contains 4,094 blocks between `0x70000000` and `0x7ffdffff`. Each reservation filename is the first ID of a block. Preserve this directory across upgrades and exclude this pool from external account directories and other dynamic ID allocators. Keep reserved IDs out of future subordinate-ID assignments. Reservations persist after exit because files on bind mounts and overlays can retain those owners. Allocation fails when the pool is exhausted. An administrator can reclaim an individual reservation after verifying that all processes, checkpoints, and files using that block are gone. Recreate existing root-remapped containers to receive fresh mappings and review host files still owned by the old 100000–165535 range.

**Agent mode is not hardened.** By design, agent mode applies several security mechanisms on a best-effort basis: seccomp and Landlock failures are warn-and-continue (with `--allow-degraded-security`), chroot fallback is available (with `--allow-chroot-fallback`), and cgroup creation failures are non-fatal. Operators requiring strict isolation for ephemeral workloads should use `--service-mode strict-agent`; operators deploying long-running NixOS services should use production mode.

## Service Modes

| Feature | Agent Mode | Strict Agent Mode | Production Mode |
|---|---|---|---|
| Service mode | `--service-mode agent` (default) | `--service-mode strict-agent` (alias: `--service-mode mitos-agent`) | `--service-mode production` |
| Degraded security | Allowed with flag | Forbidden | Forbidden |
| Chroot fallback | Allowed with flag | Forbidden | Forbidden |
| Host networking | Allowed with flag | Native `host` forbidden; `gvisor-host` allowed with gVisor + explicit opt-in | Native `host` forbidden; `gvisor-host` allowed with gVisor + explicit opt-in |
| Cgroup limits | Best-effort | Required (fatal on create/apply failure) | Required (fatal on create/apply failure) |
| Bridge DNS | No implicit resolver | Must be configured explicitly unless credential broker mode disables DNS | Must be configured explicitly unless credential broker mode disables DNS |
| Rootfs | Host bind mounts unless `--rootfs` (optionally with `--rootfs-mode overlay`) or `--agent-toolchain-rootfs` is supplied | Host bind mounts unless `--rootfs` (optionally with `--rootfs-mode overlay`) or `--agent-toolchain-rootfs` is supplied | Pre-built Nix closure (`--rootfs`) or build-time `mkImage` image without an overlay diff |
| Workspace | Optional `/workspace`; bind/copy-in-out for agents | Optional `/workspace`; bind/copy-in-out for agents | Optional, non-executable unless read-only or policy-specific |
| Bridge egress policy | Deny-all by default | Deny-all by default | Deny-all by default |
| Memory limit | Optional | Optional | Required |
| PID 1 init | Direct exec | Direct exec | Mini-init with zombie reaping + signal forwarding |
| Workload uid/gid | Container root maps to a per-launch host UID/GID block when launched as root | User namespace remapping required when running as host root | Configurable post-setup drop via `--user` / `--group` |
| Secrets | In-memory tmpfs | In-memory tmpfs | In-memory tmpfs with volatile zeroing |
| Native /proc | `hidepid=2,subset=pid` | `hidepid=2,subset=pid` | `hidepid=2,subset=pid` |
| Mount audit | Skipped | Skipped | Post-setup flag verification (fatal) |
| Seccomp trace mode | Allowed | Forbidden | Forbidden |
| Native Landlock ABI | V6 required for host networking, optional degradation with a private network namespace | V6 | V6 |
| Health checks | Optional | Optional | Optional |
| sd_notify | Optional | Optional | Optional |
| Security policies | Optional | Optional | Optional (recommended) |

Overlay rootfs mode is a writable development snapshot mode, not the strict
production posture. To support overlayfs copy-up, Nucleus retains
`CAP_DAC_OVERRIDE` and `CAP_FOWNER` in the workload and grants native Landlock
read/write/execute access to `/`. Use bind rootfs mode for the default-deny
Landlock and all-capabilities-dropped posture.

## Egress Policy

Native bridge networking defaults to deny-all in every service mode, including DNS. IPv4 allowlists apply to IPv4 only. The IPv6 OUTPUT policy permits loopback only. Bridge setup or firewall installation failure aborts launch.
The supervisor installs a dual-stack nftables OUTPUT chain in the workload network namespace. It permits loopback and IPv4 reply traffic. Use `--egress-allow` and `--egress-domain` to permit outbound destinations and restrict them with the TCP and UDP port options. DNS egress requires `--egress-dns` and explicit `--dns` resolvers. The userspace backend disables its built-in DNS proxy.

A counter records denied packets. For rate-limited kernel messages with the `nucleus-egress-denied:` prefix, enable `--egress-log-denied` on a host configured with `net.netfilter.nf_log_all_netns=1`. Startup fails if the requested logging facility is unavailable.

```bash
# Allow outbound to internal network on HTTPS only
nucleus run --network bridge --dns 10.0.0.1 \
  --egress-allow 10.0.0.0/8 --egress-tcp-port 443 \
  -- ./my-service

# Allow outbound to a provider API domain on HTTPS only
nucleus run --network bridge --dns 10.0.0.1 \
  --egress-dns --egress-domain api.example.com --egress-tcp-port 443 \
  -- ./provider-client

# Production deny-all egress, including DNS
nucleus run --service-mode production --network bridge --dns 10.0.0.1 \
  -- ./isolated-service
```

Domain entries grant access to the resolved IPv4 addresses shared by a hostname. The host resolver runs at startup and every 30 seconds. A special-use address, address on the workload subnet, or address assigned to the host causes the entire update to be rejected. A failed refresh withdraws the previous grants. The kernel expires grants after 60 seconds even if the supervisor stops. Use explicit CIDRs for intended private destinations.

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

Broker mode is mutually exclusive with `--egress-allow`, `--egress-domain`, `--egress-tcp-port`, and `--egress-udp-port`; adding direct routes would defeat the broker boundary. The broker endpoint must be the host-side IPv4 bridge gateway, not `127.0.0.1`, because loopback is local to the container namespace. The default host-side bridge gateway is `10.0.42.1`; Nucleus rejects broker IPs that differ from the configured bridge gateway.

The kernel backend requires operator-configured `net.ipv4.ip_forward=1`. It installs private nftables tables for each attachment and reclaims orphaned tables on the next kernel bridge setup. Only locally addressed traffic matches a published port. The default bridge isolates peers and restricts host input to replies, the configured credential broker, and explicitly allowed DNS. Named topology networks use their configured subnet and distinct bridge interfaces. A service may attach to one network. Members of a named kernel bridge can communicate subject to egress policy. For a named fabric, `auto` selects a kernel bridge when the supervisor runs as root. Each slirp attachment has a private network. Existing unmanaged bridges, including unmarked bridges left by older releases, must be drained and removed or a different bridge name and subnet selected before migration.

Userspace NAT requires a workload user namespace mapping container UID 0 to a nonzero host UID, access to `/dev/net/tun` by that mapped identity, and slirp4netns with sandbox and seccomp support. Helper setup failure aborts launch.

Credential broker mode currently requires the kernel bridge/veth/nftables NAT backend. It rejects explicit `--nat-backend userspace`, and `--nat-backend auto` is rejected when it would resolve to userspace NAT for rootless/native containers. `slirp4netns` does not expose the host-side bridge gateway as a host-bound address for the broker.

At startup, Nucleus performs a short TCP pre-connect to the broker endpoint after bridge setup and before releasing the workload. A missing or unreachable broker fails the sandbox start immediately instead of letting the first outbound request hang.

When broker mode is enabled, Nucleus injects `NUCLEUS_CONTAINER_ID` and `NUCLEUS_CREDENTIAL_BROKER_TOKEN` into the workload. The token is an independent random per-container value, so a broker or provider-specific wrapper can authenticate and attribute requests by sandbox. User-provided values for those keys are overwritten in broker mode.

`--credential-broker-no-proxy-env` disables automatic `HTTP_PROXY`/`HTTPS_PROXY` injection. The shorter alias `--no-broker-proxy-env` is also accepted.

A dependency-free reference broker is available at `examples/credential_broker.rs`. It audits CONNECT requests and forwards them as opaque tunnels, and it injects a static `Authorization: Bearer ...` header for plain HTTP absolute-form proxy requests. CONNECT over TLS cannot have upstream bearer headers injected unless the broker terminates TLS or the client uses a provider-specific base URL/protocol that lets the broker see the HTTP request.

## Native Bridge Backends

For the native runtime, `--network bridge` now has two backends:

| `--nat-backend` | When used | Implementation |
|---|---|---|
| `auto` | Default | Kernel bridge/veth/nftables when privileged, `slirp4netns` userspace NAT when rootless |
| `kernel` | Explicit opt-in | Kernel bridge + veth + nftables masquerade and local-destination DNAT |
| `userspace` | Explicit opt-in | `slirp4netns` userspace NAT + API-socket port forwarding |

This changes the native rootless behavior from "degrade to `none`" to a real userspace NAT path.

## gVisor Network Modes

When using gVisor (`--runtime gvisor`), the network mode is selected explicitly:

| Container `--network` | gVisor `--network` flag | Description |
|---|---|---|
| `none` | `none` | Fully isolated (default for agents) |
| `bridge` | `sandbox` | gVisor netstack uses the interface and routes in the Nucleus-prepared network namespace |
| `gvisor-host` | `host` | gVisor hostinet mode; omits the OCI network namespace and requires `--allow-host-network` |

Nucleus requires a versioned runsc release of **20260831.0 or later** for gVisor launches. The Nix package includes runsc 20261116.0 and its matching sidecars. Bridge netstack sends packets at the link layer. Nucleus therefore rejects gVisor bridge launches, including the default deny-all policy. Use native bridge for enforced egress, `--network none` for isolation, or explicitly opt into gVisor host networking.

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
- `annotations`: runtime metadata passed through to the bundle

That OCI path is the contract used with `runsc`. The native runtime uses Nucleus's direct Linux setup path rather than exposing a separate OCI CLI surface.

Configure lifecycle hooks explicitly with `nucleus create --hooks`. Hooks receive
OCI state JSON on stdin and only the environment supplied in their hook entry.
Nucleus runs hooks with empty effective, permitted, inheritable and ambient
capability sets and `no_new_privs`. Root supervisors switch hooks to UID/GID
65534 with empty supplementary groups. Native launches support all five phases.
gVisor supports supervisor-run `poststart` and `poststop`. Its three creation
and start phases require execution inside runsc and are rejected during configuration.

An explicit `--bundle` must name a new or empty directory under trusted parents.
An existing bundle directory must belong to the launching identity and its
permissions must exclude group and other writes. Host root uses
`/run/nucleus-gvisor` by default even when sudo preserves `XDG_RUNTIME_DIR`.

## Machine-Readable Events

Use `--events-jsonl <path>` to write control-plane lifecycle events as JSON Lines, or `--events-fd <fd>` to write them to an inherited file descriptor. The stream is separate from workload stdout/stderr and PTY bytes; operators can consume it without parsing user process output. `--events-fd` rejects stdio descriptors and is not available with `--detach`; use `--events-jsonl` for detached containers. `--events-fd` also implies `--quiet`, so the container ID and informational logs stay off the workload's stdout and stderr.

Events include a container start record and a final summary record. The records carry the container ID, PID, cgroup path, workspace/context mount, network mode, seccomp mode, Landlock status, capability status, resource limits, exit status, resource stats, and whether cleanup succeeded. With `--start-fd`, `container_started` is written before the workload is released, and a refused start is reported in the summary's `exit_status.error` (see [Embedding in an Orchestrator](#embedding-in-an-orchestrator)).

## Additional Hardening Flags

- `--seccomp-profile <path>` loads a custom per-service seccomp profile (OCI JSON format). Native allow rules for `clone` combine the supplied argument predicates with the built-in namespace mask. The native loader rejects unsupported argument rules.
- Native attach, exec probes, and TCP readiness probes reuse the seccomp program recorded at launch and join the configured workload cgroup. Recreate containers launched by older versions before using these helpers. Timed probe descendants share a private process group until cleanup. Calls to `setsid` and `setpgid` from these probes return `EPERM` when the workload filter permits the call.
- `--seccomp-profile-sha256 <hex>` verifies the profile's SHA-256 hash before loading.
- `--seccomp-mode trace|enforce` switches between trace (record all syscalls) and enforce (default).
- `--seccomp-log <path>` creates a new private NDJSON trace file. Use a fresh path with no symlink components. Kernel audit delivery and descendant discovery are best effort, especially for short-lived processes.
- Capability policy files in all service modes reject dangerous capabilities, including `NET_ADMIN`, `SYS_RESOURCE` and `MKNOD`.
- `--caps-policy <path>` loads a TOML capability policy (replaces default drop-all).
- `--caps-policy-sha256 <hex>` verifies the capability policy hash.
- Native bind mounts require Linux 5.12 or later for recursive mount attributes.
- Native attach and probes require the live supervisor’s original kernel Landlock ruleset and the saved seccomp policy. These helpers fail closed for legacy and restored containers without a live ruleset. Restore requires a signed checkpoint containing the original workload identity. CRIU preserves kernel UID/GID mappings. Nucleus rejects checkpoint and restore for automatically root-remapped containers, and for legacy root-created namespaces whose mapping was never recorded.
- `--landlock-policy <path>` loads a TOML Landlock filesystem policy (replaces default rules).
- `--landlock-policy-sha256 <hex>` verifies the Landlock policy hash.
- `--verify-context-integrity` hashes the source context tree before launch and verifies the populated `/context` tree matches.
- `--verify-rootfs-attestation` checks the rootfs and declared store objects against host Nix records and verifies the embedded content manifest.
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

Because the benchmark creates namespaces and cgroups, it must run as root
(`sudo -E cargo bench --bench container_runtime`). The system-level `pg18_io`
benchmark additionally supports an unprivileged path — see
[`benches/pg18_io/`](benches/pg18_io/) (`ROOTLESS=1`).

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
