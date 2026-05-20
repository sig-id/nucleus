# Filesystem Design

## Overview

Nucleus uses memory-backed filesystems (tmpfs/ramfs) for container root to achieve:
- **Zero I/O latency** - All data in RAM
- **Fast startup** - No image extraction
- **Ephemeral by default** - Data disappears on exit
- **Context pre-population** - Copy agent context before exec
- **First-class workspace** - Mount or stage a host workspace at a stable
  `/workspace` path for coding agents and tools that need a predictable cwd
- **Private home** - Mount a writable tmpfs home for provider CLIs without
  exposing the host home directory
- **Agent toolchain rootfs** - Optionally replace host runtime binds with a
  reproducible rootfs that contains provider CLIs and development tools needed
  by agent orchestrators such as Mitos

## Filesystem Types

### tmpfs (Recommended)

**Characteristics:**
- Backed by RAM + swap
- Size-limited (`size=512M` option)
- Pages can be swapped to disk under memory pressure
- Supports full POSIX semantics

**Use when:**
- Resource limits are needed
- Swap is acceptable
- POSIX features required (extended attributes, ACLs)

### ramfs

**Characteristics:**
- Backed by RAM only (no swap)
- No size limit (grows until OOM)
- Cannot be swapped out
- Simpler implementation

**Use when:**
- Guaranteed in-memory performance
- cgroup memory.max enforces limit anyway
- Maximum performance needed

## Filesystem Layout

```
/                       # tmpfs root (ephemeral)
├── context/            # Pre-populated from --context
│   ├── README.md
│   ├── src/
│   │   ├── main.rs
│   │   └── lib.rs
│   └── docs/
│       └── api.md
│
├── workspace/          # First-class workspace mount/stage
│   └── ...             # Host project tree from --workspace
│
├── home/
│   └── agent/          # Private tmpfs home, default HOME
│       └── ...         # Optional provider config mounts
│
├── bin/                # Minimal binaries
│   ├── sh            # Statically linked shell (busybox)
│   ├── ls
│   ├── cat
│   ├── grep
│   └── agent         # User's agent binary (copied or bind-mounted)
│
├── dev/                # Minimal device nodes
│   ├── null
│   ├── zero
│   ├── full
│   ├── random
│   ├── urandom
│   ├── tty
│   └── console
│
├── proc/               # procfs (mounted)
├── sys/                # sysfs (optional, usually not needed)
├── tmp/                # Writable temporary space
└── etc/                # Minimal config
    ├── passwd
    ├── group
    └── hostname
```

## Workspace Mount

`--workspace <host-path>` establishes the host project tree as a first-class
container workspace. The container destination is fixed at `/workspace`; use
regular `--volume SOURCE:DEST[:ro|rw]` only for additional mounts that are not
the primary workspace contract.

`--workdir <container-path>` selects the process working directory and defaults
to `/workspace`. The runtime creates `/workspace` even when no workspace is
configured so the default cwd is stable.

`--workspace-mode` controls how the host path is exposed:

| Mode | Behavior |
|------|----------|
| `bind-rw` | Bind-mount the host path at `/workspace` read-write. |
| `bind-ro` | Bind-mount the host path at `/workspace` read-only. |
| `copy-in-out` | Copy the host path into a private staging directory, bind the staging directory at `/workspace`, then sync the staged tree back to the host path after the workload exits. |

Workspace bind mounts are `nosuid,nodev,noexec` by default. `--workspace-exec`
removes `noexec` from the workspace mount and grants Landlock execute rights for
`/workspace`; it is intended for agent-mode build and test workflows that need
to run generated binaries. Without `--workspace-exec`, native Landlock allows
workspace reads and writes but denies execution from the workspace. Production
mode rejects writable executable workspaces; production workloads should use an
immutable rootfs plus explicit, narrow policy files instead.

## Sandbox Home and Provider Config Mounts

The workload gets a private home tmpfs at `/home/agent` by default. `--home`
selects a different absolute container path. The selected home path is mounted
as tmpfs with `nosuid,nodev,noexec`, mode `0700`, and ownership matching the
configured workload uid/gid. Nucleus sets the default `HOME` environment value
to the selected home path unless an explicit `HOME` variable is provided.

Provider credential and configuration directories must be mounted explicitly:

| Flag | Behavior |
|------|----------|
| `--provider-config-ro SOURCE:DEST` | Bind-mount a host provider config path read-only. |
| `--provider-config-rw SOURCE:DEST` | Bind-mount a host provider config path read-write for token refresh workflows. |

`DEST` may be an absolute path under the selected home, or a path relative to
the selected home. Provider config mounts are `nosuid,nodev,noexec`; read-only
mounts also carry `ro`. They intentionally use a narrower source policy than
generic `--volume` so callers can mount specific host-home credential
directories such as `$HOME/.aws` without allowing broad `/home` exposure.

## Agent Toolchain Rootfs

Agent and strict-agent workloads may use an **agent toolchain rootfs** instead
of inheriting host runtime paths. This rootfs is a Nix-built directory tree that
contains the tools an agent orchestrator expects to launch inside the sandbox:
provider CLIs such as Claude, Codex, and Gemini; shells; Git; TLS
certificates; language runtimes; compilers; and package managers.

The contract is:

- `--agent-toolchain-rootfs <path>` is accepted only in agent-style modes
  (`agent`, `strict-agent`, and the `mitos-agent` alias).
- The path must be absolute and resolve to an existing directory. Nix store
  paths are recommended because they are immutable and stable across detached
  launches.
- The runtime mounts the toolchain rootfs read-only using the same rootfs bind
  mechanism as `--rootfs`, then applies context, workspace, volumes, network
  config, and secrets as normal.
- The rootfs should provide `/bin/sh` and `/usr/bin/env` compatibility because
  provider CLIs and package-manager shims commonly rely on those paths.
- Production services should continue to use `--rootfs` with rootfs attestation
  instead of `--agent-toolchain-rootfs`.

`nucleus.lib.mkAgentToolchainRootfs` builds this rootfs contract from Nix. It
includes a broad default development toolchain and accepts provider CLI
packages so integrations can pin exactly which agent providers are available
inside the sandbox.

## Context Population

### Design Goals

1. **Fast copying** - Parallel file copies, minimal syscalls
2. **Preserve metadata** - Timestamps, permissions
3. **Filtering** - Exclude `.git`, `target/`, etc.
4. **Large context support** - Handle multi-GB contexts efficiently

### Algorithm

```rust
fn populate_context(host_path: &Path, container_path: &Path) -> Result<()> {
    // 1. Create directory structure
    create_dir_all(container_path)?;

    // 2. Walk host directory tree
    for entry in WalkDir::new(host_path)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| should_include(e))
    {
        let entry = entry?;
        let rel_path = entry.path().strip_prefix(host_path)?;
        let dest = container_path.join(rel_path);

        if entry.file_type().is_dir() {
            create_dir_all(&dest)?;
        } else if entry.file_type().is_file() {
            // Fast file copy (copy_file_range on Linux)
            copy_file(entry.path(), &dest)?;
            // Preserve metadata
            copy_metadata(entry.path(), &dest)?;
        }
        // Symlinks: optionally copy or dereference
    }

    Ok(())
}

fn should_include(entry: &DirEntry) -> bool {
    let name = entry.file_name().to_str().unwrap_or("");

    // Exclude VCS
    if name == ".git" || name == ".svn" { return false; }

    // Exclude build artifacts
    if name == "target" || name == "node_modules" { return false; }

    // Exclude editor files
    if name.starts_with(".") && name.ends_with(".swp") { return false; }

    true
}
```

### Optimization: Parallel Copying

```rust
use rayon::prelude::*;

fn populate_context_parallel(host: &Path, container: &Path) -> Result<()> {
    // 1. Collect all file paths
    let files: Vec<_> = WalkDir::new(host)
        .into_iter()
        .filter_map(|e| e.ok())
        .collect();

    // 2. Create all directories first (sequential)
    for entry in &files {
        if entry.file_type().is_dir() {
            let dest = map_path(entry.path(), host, container);
            create_dir_all(dest)?;
        }
    }

    // 3. Copy files in parallel
    files.par_iter()
        .filter(|e| e.file_type().is_file())
        .try_for_each(|entry| {
            let dest = map_path(entry.path(), host, container);
            copy_file(entry.path(), &dest)?;
            copy_metadata(entry.path(), &dest)
        })?;

    Ok(())
}
```

## Mount Operations

### Initial Mount

```rust
use nix::mount::{mount, MsFlags};

fn setup_root_filesystem() -> Result<()> {
    let root = Path::new("/tmp/nucleus-XXXXXX");

    // Mount tmpfs with size limit
    mount(
        Some("tmpfs"),
        root,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("size=512M,mode=0755")
    )?;

    // Create directory structure
    create_dir_all(root.join("context"))?;
    create_dir_all(root.join("bin"))?;
    create_dir_all(root.join("dev"))?;
    create_dir_all(root.join("tmp"))?;

    Ok(())
}
```

### Device Nodes

```rust
use nix::sys::stat::{mknod, Mode, SFlag};
use nix::unistd::{Uid, Gid};

fn create_device_nodes(dev_path: &Path) -> Result<()> {
    let devices = [
        ("null",    makedev(1, 3)),
        ("zero",    makedev(1, 5)),
        ("full",    makedev(1, 7)),
        ("random",  makedev(1, 8)),
        ("urandom", makedev(1, 9)),
    ];

    for (name, dev) in devices {
        let path = dev_path.join(name);
        mknod(
            &path,
            SFlag::S_IFCHR,
            Mode::S_IRUSR | Mode::S_IWUSR | Mode::S_IRGRP | Mode::S_IWGRP | Mode::S_IROTH | Mode::S_IWOTH,
            dev
        )?;
    }

    Ok(())
}
```

### procfs and sysfs

```rust
fn mount_pseudo_filesystems(root: &Path) -> Result<()> {
    // Mount /proc
    let proc = root.join("proc");
    create_dir_all(&proc)?;
    mount(
        Some("proc"),
        &proc,
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>
    )?;

    // Optional: Mount /sys (usually not needed for agents)
    // let sys = root.join("sys");
    // create_dir_all(&sys)?;
    // mount(Some("sysfs"), &sys, Some("sysfs"), MsFlags::empty(), None)?;

    Ok(())
}
```

### pivot_root vs chroot

**pivot_root (preferred):**
- Changes root of mount namespace
- Old root can be unmounted
- Cleaner isolation

```rust
use nix::unistd::pivot_root;

fn switch_root(new_root: &Path) -> Result<()> {
    let old_root = new_root.join("old-root");
    create_dir_all(&old_root)?;

    // Move current root to old_root
    pivot_root(new_root, &old_root)?;

    // Change to new root
    chdir("/")?;

    // Unmount old root
    umount2("/old-root", MntFlags::MNT_DETACH)?;
    remove_dir("/old-root")?;

    Ok(())
}
```

**chroot (fallback):**
- Simpler but less secure
- Old root still accessible via file descriptors
- Use when pivot_root unavailable

## Bind Mounts (Optional)

For persistent storage or read-only data:

```rust
fn bind_mount_host_path(src: &Path, dest: &Path, readonly: bool) -> Result<()> {
    create_dir_all(dest)?;

    let mut flags = MsFlags::MS_BIND;
    mount(Some(src), dest, None::<&str>, flags, None::<&str>)?;

    if readonly {
        flags |= MsFlags::MS_RDONLY | MsFlags::MS_REMOUNT;
        mount(Some(src), dest, None::<&str>, flags, None::<&str>)?;
    }

    Ok(())
}
```

## Performance Characteristics

| Operation | Latency | Notes |
|-----------|---------|-------|
| tmpfs mount | ~1ms | One-time setup |
| Context copy (10MB) | ~5ms | Parallel copying |
| Context copy (1GB) | ~500ms | Memory bandwidth limited |
| File read/write | <1μs | RAM latency |
| pivot_root | ~1ms | One-time switch |

## Future Optimizations

1. **Copy-on-write** - Share readonly context across containers
2. **mmap-based copying** - Use splice(2) or copy_file_range(2)
3. **Lazy population** - FUSE overlay to load on demand
4. **Compression** - Compress context in memory (zstd)
5. **Content-addressable storage** - Deduplicate common files
