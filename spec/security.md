# Security Model

## Threat Model

Nucleus assumes:
- **Untrusted workloads** - Agent code may be malicious or compromised
- **Host kernel is trusted** - We rely on Linux kernel isolation primitives
- **No lateral movement** - Containers should not escape or affect each other
- **Resource exhaustion prevention** - Malicious agents should not DoS the host

## Defense in Depth

Nucleus employs multiple layers of security:

### 1. Namespaces (Isolation)

**PID Namespace:**
- Container sees only its own processes
- Cannot signal or inspect host processes
- Init process (PID 1) inside container

**Mount Namespace:**
- Isolated filesystem view
- Host mounts are invisible
- tmpfs root prevents persistence

**Network Namespace:**
- No network access by default (None mode)
- Optional host mode shares host network stack
- Optional bridge mode with controlled NAT

**UTS Namespace:**
- Isolated hostname/domainname
- Prevents information leakage

**IPC Namespace:**
- Isolated System V IPC, POSIX message queues
- No shared memory with host

**User Namespace (optional):**
- UID/GID remapping
- Root inside container = unprivileged outside
- Enables rootless containers

### 2. Capabilities (Privilege Reduction)

Default: **Drop all capabilities** (bounding, effective, inheritable, permitted, ambient)

Can be configured via external TOML policy file (`--caps-policy`):

```toml
# Drop everything (default)
[bounding]
keep = []

# Or keep specific capabilities:
# [bounding]
# keep = ["NET_BIND_SERVICE"]
```

Minimal set if needed:
- `CAP_NET_BIND_SERVICE` - Bind to ports < 1024 (if networking enabled)
- `CAP_SETUID/CAP_SETGID` - Only if agent needs user switching

**Blocked capabilities:**
- `CAP_SYS_ADMIN` - Mount, pivot_root, etc.
- `CAP_SYS_MODULE` - Load kernel modules
- `CAP_SYS_RAWIO` - Direct disk access
- `CAP_SYS_BOOT` - Reboot system
- `CAP_SYS_PTRACE` - Trace arbitrary processes

### 3. Seccomp (Syscall Filtering)

**Three modes of operation:**

1. **Built-in allowlist** (default) – ~100 syscalls, network-aware, argument-level filtering on `socket()`, `ioctl()`, `prctl()`, `clone()`
2. **Custom JSON profile** (`--seccomp-profile`) – OCI-format syscall allowlist loaded from file with optional SHA-256 verification
3. **Trace mode** (`--seccomp-mode trace`) – allow-all with `SECCOMP_FILTER_FLAG_LOG` for profile generation; development only, rejected in production

**Profile generation workflow:**
```bash
# Record syscalls in trace mode
nucleus run --seccomp-mode trace --seccomp-log trace.ndjson -- ./my-service
# Generate minimal profile
nucleus seccomp generate trace.ndjson -o my-service.seccomp.json
# Enforce in production
nucleus run --seccomp-profile my-service.seccomp.json --seccomp-profile-sha256 abc... -- ./my-service
```

**Built-in allowlist includes:**
```
read, write, open, openat, close, stat, fstat, lstat
mmap, munmap, mprotect, brk
clone, fork, execve, wait4, exit, exit_group
getpid, gettid, getuid, getgid
socket, connect, send, recv (if networking)
landlock_create_ruleset, landlock_add_rule, landlock_restrict_self
...
```

**Blocked syscalls:**
```
ptrace          # Process tracing
kexec_load      # Load new kernel
add_key         # Kernel keyring
request_key
keyctl
bpf             # eBPF program loading
perf_event_open # Performance monitoring
userfaultfd     # User fault handling
io_uring        # Async I/O (potential escape vector)
```

Notes:
- x32 legacy syscall numbers (512-547) are not allowlisted and are denied by default.
- Landlock syscalls are allowlisted only to enable post-seccomp Landlock bootstrap in runtime setup.
- `--seccomp-log-denied` enables kernel-level logging of denied syscalls via `SECCOMP_FILTER_FLAG_LOG`.

### 4. Landlock (Filesystem Access Control)

**Path-based access restrictions using Linux LSM (kernel 5.13+):**

Applied after pivot_root, Landlock restricts what the container process can do with files it can see.

**Default policy** (when no `--landlock-policy` file is provided):

| Path | Access |
|------|--------|
| `/bin`, `/usr`, `/sbin` | Read + Execute |
| `/lib`, `/lib64`, `/lib32` | Read |
| `/etc`, `/dev`, `/proc` | Read |
| `/tmp` | Full (read, write, create, remove) |
| `/context` | Read-only |
| `/workspace` | Read/write or read-only according to `--workspace-mode`; no execute unless `--workspace-exec` |
| configured home (`/home/agent` by default) | Read/write/create/remove; no execute |
| `/` | Directory traversal only (ReadDir) |
| Everything else | **Denied** |

Workspace execution is explicit. Native Landlock denies execute on writable
workspace mounts by default, matching the `noexec` mount option used for
workspace bind and staging mounts. `--workspace-exec` is an agent-mode escape
hatch for build/test workflows and grants execute on `/workspace`; production
mode rejects writable executable workspaces to avoid drop-and-exec attacks.
OCI/gVisor receives the same mount contract through bundle mount options:
workspace mounts are `nosuid,nodev,noexec` unless `--workspace-exec` is set.

The sandbox home is a private tmpfs and is writable by the workload, but not
executable. Provider configuration mounts are explicit exceptions under that
home. Read-only provider mounts rely on both mount-level `ro` and the default
no-execute policy; read-write provider mounts are only for tools that need to
refresh local token caches.

**Custom policy** (via `--landlock-policy <path>.toml`):
```toml
min_abi = 3

[[rules]]
path = "/bin"
access = ["read", "execute"]

[[rules]]
path = "/run/secrets"
access = ["read"]

[[rules]]
path = "/tmp"
access = ["read", "write", "create", "remove"]
```

Access flags: `read`, `write`, `execute`, `create`, `remove`, `readdir`, `all`.

**Properties:**
- Irreversible once applied (kernel-enforced)
- Stackable with seccomp and capabilities (independent enforcement)
- Unprivileged (works in rootless mode)
- Graceful degradation on kernels without Landlock support
- Production mode requires Landlock ABI V3+ (adds `LANDLOCK_ACCESS_FS_TRUNCATE`)
- Policy file integrity verified via optional `--landlock-policy-sha256`

**Why this matters:**
Even if an attacker escapes the mount namespace (e.g., via a kernel bug), Landlock's LSM-level enforcement remains as an independent barrier. Namespaces control what you *see*; Landlock controls what you can *do* with what you see.

### 5. cgroups (Resource Limits)

**Memory limits:**
- `memory.max` - Hard limit, OOM kill if exceeded
- `memory.high` - Soft limit, throttling threshold
- `memory.swap.max` - Swap limit (usually disabled)

**CPU limits:**
- `cpu.max` - CPU bandwidth (e.g., 200000/100000 = 2 cores)
- `cpu.weight` - Relative share

**I/O limits:**
- `io.max` - IOPS and bandwidth limits per device

**PID limits:**
- `pids.max` - Maximum number of processes (prevent fork bombs)

### 6. gVisor Integration (Optional)

When `--runtime gvisor`:
- Use runsc (gVisor runtime)
- Intercept syscalls via ptrace or KVM
- Implement syscalls in userspace
- Reduced kernel attack surface (~70 syscalls → ~200 gVisor syscalls)

**Trade-offs:**
- Stronger isolation
- Smaller kernel attack surface
- Performance overhead (~10-30%)
- Some syscalls unsupported

### 7. Container Ownership

**Access control for multi-container management:**
- `creator_uid` stored in container state
- Attach requires root or same `creator_uid`
- Prevents unprivileged users from accessing others' containers

### 8. Checkpoint Security

**CRIU checkpoint/restore security considerations:**
- Output directory created with mode 0o700 (process memory may contain secrets)
- Requires root (`CAP_SYS_PTRACE`)
- Rootless mode returns error (not silently degraded)

### 9. Networking Security

**None mode (default):**
- Complete network isolation
- No egress or ingress traffic possible

**Host mode:**
- Full host network access (explicit opt-in)
- No additional isolation

**Bridge mode:**
- Controlled NAT via iptables
- Port forwarding limited to explicitly published ports
- Requires root (degrades to None in rootless with warning)
- Container IP in private subnet (10.0.42.0/24)

### 10. Structured Audit Log

All security-critical actions emit structured JSON events via `tracing::info!(target: "nucleus::audit", ...)`:

- `ContainerStart` / `ContainerStop` – lifecycle events
- `CapabilitiesDropped` – all caps cleared or policy applied
- `SeccompApplied` / `SeccompProfileLoaded` – filter enforcement
- `LandlockApplied` – filesystem policy locked
- `MountAuditPassed` – post-setup mount flag verification
- `NoNewPrivsSet` – `PR_SET_NO_NEW_PRIVS` applied
- `InitSupervisorStarted` – PID 1 mini-init active

Events include container ID, name, timestamp, and detail string.

### 11. Strict Agent Mode

Strict agent mode (`--service-mode strict-agent`, alias `--service-mode mitos-agent`, or `--strict-agent`) is for ephemeral agent workloads that need production-style fail-closed isolation without production service packaging.

It enforces these startup invariants:

- **Cgroups required**: cgroup creation and configured limit application are fatal on failure.
- **pivot_root required**: native runtime must switch root with `pivot_root`; `chroot` fallback is rejected.
- **Seccomp required**: seccomp must be in enforce mode and successfully installed; trace mode is rejected.
- **Landlock required on native**: native runtime must fully enforce Landlock policy.
- **User namespace remapping required when needed**: rootless launches and host-root launches must have valid UID/GID maps; mapping failures are fatal.
- **Network default none**: no network remains the default. Bridge networking must specify DNS explicitly, and native host networking is rejected.
- **Domain-aware egress**: `--egress-domain` entries are exact DNS names resolved to IPv4 `/32` rules at startup; wildcard domains and packet-time DNS matching are out of scope.
- **Credential broker egress**: `--credential-broker IPv4:PORT` is mutually exclusive with direct egress allowlists. It denies sandbox DNS and allows only TCP to the host-side broker endpoint; the broker keeps bearer credentials outside the sandbox and enforces upstream method/path/destination limits.
- **No argv secret env**: provider launchers can pass sensitive environment values through `--env-fd` instead of placing them in process argv.

It intentionally does not require production service inputs:

- No mandatory Nix rootfs or rootfs attestation.
- No mandatory health checks, readiness probes, or sd_notify.
- No systemd or NixOS module deployment semantics.
- No production PID 1 mini-init requirement; strict agents still exec directly.

Strict agents may still choose an immutable runtime surface with
`--agent-toolchain-rootfs <path>`. That path is an agent-specific rootfs used to
launch provider CLIs and development tools inside the sandbox without exposing
host `/bin`, `/usr`, `/lib`, or `/nix` runtime binds. It is not a production
service requirement, and production mode must use `--rootfs` plus attestation.

### 12. Production Mode Hardening

Production mode (`--service-mode production`) enforces additional invariants:

- **PID 1 init**: Fork-based mini-init with zombie reaping (`waitpid(-1, WNOHANG)`) and signal forwarding (SIGTERM/SIGINT/SIGHUP to child)
- **In-memory secrets**: 16MB tmpfs at `/run/secrets`, source buffers zeroed with `write_volatile`
- **Mount audit**: Verifies mount flags (MS_RDONLY, MS_NOSUID, MS_NODEV) on security-sensitive paths post-setup; fatal on mismatch
- **hidepid=2**: `/proc` mounted with `hidepid=2` to hide other processes
- **Landlock ABI**: Requires V3 minimum (adds truncate protection)
- **Deny-all egress**: Default egress policy when no `--egress-allow` or `--egress-domain` is specified
- **Seccomp trace forbidden**: `--seccomp-mode trace` rejected at config validation

### 13. Security Policy File Architecture

Security policy is separated from structural configuration (Nix) for auditability and independent change cadence:

| Concern | Format | Why separate |
|---------|--------|-------------|
| Seccomp syscall allowlist | JSON (OCI format) | 100-300 lines, generated by tooling, audited by security team |
| Capability bounding set | TOML | Changes with CVEs, not deployments |
| Landlock filesystem rules | TOML | Per-service access needs, distinct from topology |

All policy files support SHA-256 pinning for supply-chain integrity. Nix pins the hash at build time; Nucleus verifies at load time.

## Attack Scenarios

### 1. Container Escape

**Attack:** Exploit kernel vulnerability to break out of namespace

**Mitigations:**
- Seccomp blocks dangerous syscalls
- Capabilities prevent privileged operations
- Landlock restricts filesystem access at LSM level (independent of namespaces)
- gVisor reduces kernel attack surface
- User namespaces (rootless mode)

**Residual risk:** Zero-day kernel exploit

### 2. Resource Exhaustion

**Attack:** Consume all host memory/CPU

**Mitigations:**
- cgroup memory.max enforces hard limits
- cgroup cpu.max throttles CPU usage
- pids.max prevents fork bombs

**Residual risk:** None (enforced by kernel)

### 3. Information Disclosure

**Attack:** Read host files or other containers' data

**Mitigations:**
- Mount namespace isolation
- tmpfs root (no host filesystem access)
- No bind mounts by default
- Landlock restricts file operations even within visible paths
- Container ownership (creator_uid) for attach

**Residual risk:** Minimal (requires explicit bind mount)

### 4. Privilege Escalation

**Attack:** Gain root on host via setuid binary

**Mitigations:**
- All capabilities dropped
- No setuid binaries in tmpfs
- User namespace remapping (rootless)

**Residual risk:** Minimal

### 5. Network-Based Attacks

**Attack:** Reach internal services or exfiltrate data

**Mitigations:**
- No networking by default
- Bridge mode requires explicit opt-in and root
- Only published ports are forwarded
- Rootless cannot enable bridge mode

**Residual risk:** Depends on network mode chosen

### 6. Side Channel Attacks

**Attack:** Spectre/Meltdown, cache timing

**Mitigations:**
- cgroup CPU isolation (partial)
- gVisor reduces some attack surface

**Residual risk:** High (kernel mitigations depend on CPU/kernel version)

## Security Best Practices

### For Nucleus Users

1. **Never mount sensitive host paths** - Avoid unnecessary bind mounts
2. **Use minimal resource limits** - Don't over-provision
3. **Enable gVisor for untrusted code** - `--runtime gvisor`
4. **Run rootless when possible** - Use user namespaces
5. **Keep kernel updated** - Security patches are critical
6. **Use `--network none` unless needed** - Default is safest
7. **Use `--context-mode bind` carefully** - Read-only but exposes host filesystem structure

### For Nucleus Developers

1. **Fail closed** - Deny by default, allow on opt-in
2. **Validate all inputs** - Paths, resource limits, etc.
3. **Use safe Rust** - Avoid `unsafe` except for FFI
4. **Audit syscall whitelist** - Review seccomp filter regularly
5. **Test against exploits** - Run security benchmarks

## Comparison to Docker/runc

| Security Feature | Docker/runc | Nucleus |
|------------------|-------------|---------|
| Namespaces | All 6 | All 8 (including cgroup, time) |
| Capabilities | Drop most | Drop all (default), configurable via TOML |
| Seccomp | Whitelist (~300) | Whitelist (~100), per-service JSON profiles, trace-based generation |
| Landlock | No | Yes (path-based ACLs), configurable via TOML |
| cgroups | v1/v2 | v2 only |
| Rootless | Yes | Yes |
| gVisor | Optional | Optional |
| AppArmor/SELinux | Yes | Landlock (kernel-native) |
| Networking | Full CNI | None/Host/Bridge + deny-all egress |
| Multi-container | Docker Compose | Nucleus Compose (TOML, DAG, reconciliation) |
| Secrets | Docker secrets, tmpfs | In-memory tmpfs with volatile zeroing |
| Audit log | Docker events | Structured JSON audit events |
| Profile generation | N/A | Trace mode + `seccomp generate` |
| Policy integrity | N/A | SHA-256 pinning on all policy files |
| PID 1 init | tini/dumb-init | Built-in mini-init (production mode) |
| Checkpoint | Optional (CRIU) | Optional (CRIU) |
| Ownership | Root/socket | creator_uid |

Nucleus aims for a **smaller attack surface** by:
- No daemon (smaller code)
- Stricter seccomp defaults with per-service profiling
- Ephemeral-only (no persistence concerns)
- Simpler design (fewer features = fewer bugs)
- No networking by default
- SHA-256 integrity verification on all security policy files
