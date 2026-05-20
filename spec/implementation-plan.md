# Implementation Plan

## Phase 1: Core Infrastructure (Week 1)

### 1.1 Project Setup
- [x] Initialize Cargo project
- [x] Set up Nix flake with Rust toolchain
- [x] Configure CI/CD (GitHub Actions)
- [x] Add dependencies: clap, nix, anyhow, thiserror

### 1.2 CLI Interface
- [x] Implement argument parsing with clap
- [x] Document stable programmatic launch config via `nucleus run --config` and `--config-fd`
- [x] Validate input parameters
- [x] Parse resource limits (512M, 1G, etc.)
- [x] Add --help and --version

### 1.3 Error Handling
- [x] Define error types
- [x] Implement From<T> for common errors
- [x] Add context with anyhow

## Phase 2: Filesystem Layer (Week 2)

### 2.1 tmpfs Management
- [x] Implement tmpfs mounting with nix::mount
- [x] Add size limits
- [x] Handle mount flags (nosuid, nodev, noexec)
- [x] Cleanup on drop

### 2.2 Context Population
- [x] Walk source directory tree
- [x] Copy files with metadata
- [x] Filter excluded patterns (.git, target/, etc.)
- [x] Symlink handling (skip for security)

### 2.3 Minimal Filesystem
- [x] Create /bin, /dev, /tmp, /proc directories
- [x] Create device nodes (null, zero, random, urandom)
- [x] Mount procfs

## Phase 3: Isolation Layer (Week 3)

### 3.1 Namespace Management
- [x] Implement unshare(2) wrapper
- [x] Configure all 6 namespace types
- [x] Set hostname in UTS namespace
- [x] User namespace UID/GID mapping (for rootless)

### 3.2 Root Filesystem Switch
- [x] Implement pivot_root(2) wrapper
- [x] Fallback to chroot(2) if pivot_root fails
- [x] Unmount old root after pivot
- [x] Change working directory to /

## Phase 4: Resource Control (Week 4)

### 4.1 cgroup v2 Interface
- [x] Create cgroup hierarchy
- [x] Write to memory.max, cpu.max, pids.max
- [x] Attach process via cgroup.procs
- [x] Cleanup cgroup on exit

### 4.2 Resource Monitoring
- [x] Read memory.current, memory.stat
- [x] Parse cpu.stat
- [x] Read pids.current
- [x] Format stats for output

## Phase 5: Security Layer (Week 5)

### 5.1 Capability Dropping
- [x] Wrapper around cap_set_proc(3)
- [x] Drop all capabilities by default

### 5.2 Seccomp Filters
- [x] Define syscall whitelist
- [x] Build BPF filter program
- [x] Apply filter via prctl(PR_SET_SECCOMP)

### 5.3 Landlock Filesystem Policy
- [x] Define path-based access rules (read-only context, r+w /tmp, r+x binaries)
- [x] Build Landlock ruleset using ABI V5
- [x] Apply via restrict_self()
- [x] Best-effort mode for kernels without Landlock

### 5.4 gVisor Integration (Optional)
- [x] Detect runsc binary
- [x] Exec via runsc instead of direct exec
- [x] OCI bundle support

## Phase 6: Process Execution (Week 6)

### 6.1 Container Init
- [x] Orchestrate all setup steps
- [x] Fork child process for namespace isolation
- [x] Parent waits for child, monitors
- [x] Handle errors and cleanup

### 6.2 Process Management
- [x] execve(2) wrapper
- [x] Handle signals (SIGTERM, SIGKILL)
- [x] Reap zombie processes
- [x] PTY/console mode with controlling TTY, OCI console socket handoff, and raw byte stream semantics

## Phase 7: Testing & Documentation (Week 7)

### 7.1 Integration Tests
- [x] End-to-end container lifecycle
- [x] Security isolation verification
- [x] Context population correctness

### 7.2 Documentation
- [x] README.md with usage examples
- [x] Architecture documentation
- [x] Security model documentation

### 7.3 Benchmarks
- [x] Context population speed
- [x] Resource configuration
- [x] Seccomp filter application
- [x] Concurrency

## Phase 8: Long-Term Features

### 8.1 Multi-Container Support
- [x] Unique container IDs (12 hex chars from timestamp+PID hash)
- [x] Container naming (`--name` flag)
- [x] Container resolution (exact ID, name, or ID prefix)
- [x] `nucleus stop` with graceful SIGTERM → timeout → SIGKILL
- [x] `nucleus kill` with arbitrary signal support
- [x] `nucleus rm` with optional `--force`
- [x] `creator_uid` tracking for ownership

### 8.2 Container Attach
- [x] Enter running container namespaces via `setns(2)`
- [x] Fork/exec pattern with configurable command
- [x] Ownership validation (root or same `creator_uid`)

### 8.3 Optional Networking
- [x] None mode (default, fully isolated)
- [x] Host mode (share host network namespace)
- [x] Bridge mode (veth pairs, NAT, iptables)
- [x] Port forwarding (`-p HOST:CONTAINER[/PROTOCOL]`)
- [x] DNS configuration (`/etc/resolv.conf`)
- [x] Rootless degradation (bridge requires root)

### 8.4 CRIU Checkpoint/Restore
- [x] Checkpoint via `criu dump`
- [x] Restore via `criu restore`
- [x] Metadata storage alongside dump images
- [x] Secure output directory (mode 0o700)
- [x] Root-only (CRIU requires `CAP_SYS_PTRACE`)

### 8.5 Context Streaming
- [x] Copy mode (traditional, backward compatible)
- [x] Bind mount mode (zero-copy, instant access)
- [x] Read-only bind mount for security
- [x] Pre-pivot_root bind mount

## Success Criteria

- [x] Can run simple container with isolation
- [x] Resource limits enforced (memory, CPU, PIDs)
- [x] All security layers active (namespaces, caps, seccomp, Landlock)
- [x] Context pre-populated before execution
- [x] Startup time < 50ms (target: < 10ms)
- [x] All tests passing
- [x] Documentation complete
- [x] Multi-container lifecycle management
- [x] Container attach for debugging
- [x] Optional networking for API access
- [x] Checkpoint/restore for migration
- [x] Context streaming for large datasets
