use super::attestation::{is_immediate_nix_store_object_path, ROOTFS_STORE_PATHS_FILE};
use crate::error::{NucleusError, Result};
use nix::fcntl::{open, OFlag};
use nix::mount::{mount, MsFlags};
use nix::sys::stat::{fstat, makedev, mknod, Mode, SFlag};
use nix::unistd::chroot;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use tracing::{debug, info, warn};

/// Expected mount flags for audit verification.
struct ExpectedMount {
    path: &'static str,
    required_flags: &'static [&'static str],
    /// If true, the mount *must* exist in production mode. A missing critical
    /// mount (e.g. /proc) is treated as a violation rather than silently skipped.
    critical: bool,
}

/// Known mount paths and the flags they must carry in production mode.
const PRODUCTION_MOUNT_EXPECTATIONS: &[ExpectedMount] = &[
    ExpectedMount {
        path: "/bin",
        required_flags: &["ro", "nosuid", "nodev"],
        critical: true,
    },
    ExpectedMount {
        path: "/usr",
        required_flags: &["ro", "nosuid", "nodev"],
        critical: true,
    },
    ExpectedMount {
        path: "/lib",
        required_flags: &["ro", "nosuid", "nodev"],
        critical: false, // not all rootfs layouts have /lib
    },
    ExpectedMount {
        path: "/lib64",
        required_flags: &["ro", "nosuid", "nodev"],
        critical: false, // not all rootfs layouts have /lib64
    },
    ExpectedMount {
        path: "/etc",
        required_flags: &["ro", "nosuid", "nodev"],
        critical: true,
    },
    ExpectedMount {
        path: "/nix",
        required_flags: &["ro", "nosuid", "nodev"],
        critical: false, // only present on NixOS-based rootfs
    },
    ExpectedMount {
        path: "/sbin",
        required_flags: &["ro", "nosuid", "nodev"],
        critical: false, // not all rootfs layouts have /sbin
    },
    ExpectedMount {
        path: "/proc",
        required_flags: &["nosuid", "nodev", "noexec"],
        critical: true,
    },
    ExpectedMount {
        path: "/run/secrets",
        required_flags: &["nosuid", "nodev", "noexec"],
        critical: false, // only present when secrets are configured
    },
];

/// Normalize an absolute container destination path and reject traversal.
///
/// Returns a normalized absolute path containing only `RootDir` and `Normal`
/// components. `.` segments are ignored; `..` and relative paths are rejected.
pub fn normalize_container_destination(dest: &Path) -> Result<PathBuf> {
    if !dest.is_absolute() {
        return Err(NucleusError::ConfigError(format!(
            "Container destination must be absolute: {:?}",
            dest
        )));
    }

    let mut normalized = PathBuf::from("/");
    let mut saw_component = false;

    for component in dest.components() {
        match component {
            Component::RootDir => {}
            Component::CurDir => {}
            Component::Normal(part) => {
                normalized.push(part);
                saw_component = true;
            }
            Component::ParentDir => {
                return Err(NucleusError::ConfigError(format!(
                    "Container destination must not contain parent traversal: {:?}",
                    dest
                )));
            }
            Component::Prefix(_) => {
                return Err(NucleusError::ConfigError(format!(
                    "Unsupported container destination prefix: {:?}",
                    dest
                )));
            }
        }
    }

    if !saw_component {
        return Err(NucleusError::ConfigError(format!(
            "Container destination must not be the root directory: {:?}",
            dest
        )));
    }

    Ok(normalized)
}

/// Resolve a validated container destination under a host-side root directory.
pub fn resolve_container_destination(root: &Path, dest: &Path) -> Result<PathBuf> {
    let normalized = normalize_container_destination(dest)?;
    let relative = normalized.strip_prefix("/").map_err(|_| {
        NucleusError::ConfigError(format!(
            "Container destination is not absolute after normalization: {:?}",
            normalized
        ))
    })?;
    Ok(root.join(relative))
}

fn validate_rootfs_path_under_store(rootfs_path: &Path, store_root: &Path) -> Result<PathBuf> {
    if !rootfs_path.is_absolute() {
        return Err(NucleusError::ConfigError(format!(
            "Production rootfs path must be absolute: {}",
            rootfs_path.display()
        )));
    }

    for component in rootfs_path.components() {
        match component {
            Component::ParentDir => {
                return Err(NucleusError::ConfigError(format!(
                    "Production rootfs path must not contain parent traversal: {}",
                    rootfs_path.display()
                )));
            }
            Component::Prefix(_) => {
                return Err(NucleusError::ConfigError(format!(
                    "Unsupported production rootfs path prefix: {}",
                    rootfs_path.display()
                )));
            }
            Component::RootDir | Component::CurDir | Component::Normal(_) => {}
        }
    }

    let canonical = std::fs::canonicalize(rootfs_path).map_err(|e| {
        NucleusError::ConfigError(format!(
            "Failed to canonicalize production rootfs path '{}': {}",
            rootfs_path.display(),
            e
        ))
    })?;

    if !canonical.starts_with(store_root) {
        return Err(NucleusError::ConfigError(format!(
            "Production mode requires rootfs path to resolve under {}: {} -> {}",
            store_root.display(),
            rootfs_path.display(),
            canonical.display()
        )));
    }

    if !canonical.is_dir() {
        return Err(NucleusError::ConfigError(format!(
            "Production rootfs path must resolve to a directory: {}",
            canonical.display()
        )));
    }

    Ok(canonical)
}

/// Validate a production rootfs path and return the canonical path to use.
///
/// Production rootfs paths must not contain parent traversal, and the resolved
/// target must be a directory under the immutable Nix store.
pub fn validate_production_rootfs_path(rootfs_path: &Path) -> Result<PathBuf> {
    validate_rootfs_path_under_store(rootfs_path, Path::new("/nix/store"))
}

/// Validate an agent toolchain rootfs path and return the canonical path to use.
///
/// Agent toolchain rootfs paths are not restricted to `/nix/store` because
/// local development and tests may build them elsewhere, but they must be
/// absolute, traversal-free, and resolve to an existing directory.
pub fn validate_agent_toolchain_rootfs_path(rootfs_path: &Path) -> Result<PathBuf> {
    if !rootfs_path.is_absolute() {
        return Err(NucleusError::ConfigError(format!(
            "Agent toolchain rootfs path must be absolute: {}",
            rootfs_path.display()
        )));
    }

    for component in rootfs_path.components() {
        match component {
            Component::ParentDir => {
                return Err(NucleusError::ConfigError(format!(
                    "Agent toolchain rootfs path must not contain parent traversal: {}",
                    rootfs_path.display()
                )));
            }
            Component::Prefix(_) => {
                return Err(NucleusError::ConfigError(format!(
                    "Unsupported agent toolchain rootfs path prefix: {}",
                    rootfs_path.display()
                )));
            }
            Component::RootDir | Component::CurDir | Component::Normal(_) => {}
        }
    }

    let canonical = std::fs::canonicalize(rootfs_path).map_err(|e| {
        NucleusError::ConfigError(format!(
            "Failed to canonicalize agent toolchain rootfs path '{}': {}",
            rootfs_path.display(),
            e
        ))
    })?;

    if !canonical.is_dir() {
        return Err(NucleusError::ConfigError(format!(
            "Agent toolchain rootfs path must resolve to a directory: {}",
            canonical.display()
        )));
    }

    Ok(canonical)
}

pub(crate) fn read_regular_file_nofollow(path: &Path) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to open file {:?} with O_NOFOLLOW: {}",
                path, e
            ))
        })?;

    let metadata = file.metadata().map_err(|e| {
        NucleusError::FilesystemError(format!("Failed to stat file {:?}: {}", path, e))
    })?;
    if !metadata.is_file() {
        return Err(NucleusError::FilesystemError(format!(
            "Expected regular file for {:?}, found non-file source",
            path
        )));
    }

    let mut content = Vec::new();
    file.read_to_end(&mut content).map_err(|e| {
        NucleusError::FilesystemError(format!("Failed to read file {:?}: {}", path, e))
    })?;
    Ok(content)
}

fn decode_mountinfo_field(field: &str) -> String {
    let mut decoded = String::with_capacity(field.len());
    let mut chars = field.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            let code: String = chars.by_ref().take(3).collect();
            match code.as_str() {
                "040" => decoded.push(' '),
                "011" => decoded.push('\t'),
                "012" => decoded.push('\n'),
                "134" => decoded.push('\\'),
                _ => {
                    decoded.push('\\');
                    decoded.push_str(&code);
                }
            }
        } else {
            decoded.push(ch);
        }
    }

    decoded
}

fn parse_mountinfo_line(line: &str) -> Option<(String, std::collections::HashSet<String>)> {
    let (left, _) = line.split_once(" - ")?;
    let fields: Vec<&str> = left.split_whitespace().collect();
    if fields.len() < 6 {
        return None;
    }

    let mount_point = decode_mountinfo_field(fields[4]);
    let options = fields[5]
        .split(',')
        .map(str::trim)
        .filter(|opt| !opt.is_empty())
        .map(str::to_string)
        .collect();

    Some((mount_point, options))
}

/// Audit all mounts in the container's mount namespace.
///
/// Reads `/proc/self/mountinfo` and verifies that each known mount point carries
/// its expected per-mount flags. In production mode, any missing flag is fatal.
/// Returns Ok(()) if all checks pass, or a list of violations.
pub fn audit_mounts(production_mode: bool) -> Result<()> {
    let mounts_content = std::fs::read_to_string("/proc/self/mountinfo").map_err(|e| {
        NucleusError::FilesystemError(format!("Failed to read /proc/self/mountinfo: {}", e))
    })?;
    let mount_table: std::collections::HashMap<String, std::collections::HashSet<String>> =
        mounts_content
            .lines()
            .filter_map(parse_mountinfo_line)
            .collect();

    let mut violations = Vec::new();

    for expectation in PRODUCTION_MOUNT_EXPECTATIONS {
        if let Some(options) = mount_table.get(expectation.path) {
            for &flag in expectation.required_flags {
                if !options.contains(flag) {
                    let rendered = options
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .join(",");
                    violations.push(format!(
                        "Mount {} missing required flag '{}' (has: {})",
                        expectation.path, flag, rendered
                    ));
                }
            }
        } else if expectation.critical && production_mode {
            violations.push(format!(
                "Critical mount {} is missing from the mount namespace",
                expectation.path
            ));
        }
    }

    if violations.is_empty() {
        info!("Mount audit passed: all expected flags verified");
        Ok(())
    } else if production_mode {
        Err(NucleusError::FilesystemError(format!(
            "Mount audit failed in production mode:\n  {}",
            violations.join("\n  ")
        )))
    } else {
        for v in &violations {
            warn!("Mount audit: {}", v);
        }
        Ok(())
    }
}

/// Create minimal filesystem structure in the new root
pub fn create_minimal_fs(root: &Path) -> Result<()> {
    info!("Creating minimal filesystem structure at {:?}", root);

    // Create essential directories
    let dirs = vec![
        "dev",
        "proc",
        "sys",
        "tmp",
        "bin",
        "sbin",
        "usr",
        "lib",
        "lib64",
        "etc",
        "nix",
        "nix/store",
        "run",
        "context",
        "workspace",
        "home",
        "home/agent",
    ];

    for dir in dirs {
        let path = root.join(dir);
        std::fs::create_dir_all(&path).map_err(|e| {
            NucleusError::FilesystemError(format!("Failed to create directory {:?}: {}", path, e))
        })?;
    }

    info!("Created minimal filesystem structure");

    Ok(())
}

/// Create essential device nodes in /dev
///
/// In rootless mode, device node creation will fail gracefully
pub fn create_dev_nodes(dev_path: &Path, include_tty: bool) -> Result<()> {
    info!("Creating device nodes at {:?}", dev_path);

    // Device nodes: (name, type, major, minor)
    let mut devices = vec![
        ("null", SFlag::S_IFCHR, 1, 3),
        ("zero", SFlag::S_IFCHR, 1, 5),
        ("full", SFlag::S_IFCHR, 1, 7),
        ("random", SFlag::S_IFCHR, 1, 8),
        ("urandom", SFlag::S_IFCHR, 1, 9),
    ];
    if include_tty {
        devices.push(("tty", SFlag::S_IFCHR, 5, 0));
    }

    let mut created_count = 0;
    let mut failed_count = 0;

    for (name, dev_type, major, minor) in devices {
        let path = dev_path.join(name);
        let mode = Mode::from_bits_truncate(0o660);
        let dev = makedev(major, minor);

        match mknod(&path, dev_type, mode, dev) {
            Ok(_) => {
                info!("Created device node: {:?}", path);
                created_count += 1;
            }
            Err(e) => {
                // In rootless mode, mknod fails - this is expected
                warn!(
                    "Failed to create device node {:?}: {} (this is normal in rootless mode)",
                    path, e
                );
                failed_count += 1;
            }
        }
    }

    if created_count > 0 {
        info!("Successfully created {} device nodes", created_count);
    }
    if failed_count > 0 {
        info!("Skipped {} device nodes (rootless mode)", failed_count);
    }

    Ok(())
}

/// Bind mount a pre-built rootfs (e.g. a Nix store closure) into the container.
///
/// Instead of exposing the full host /bin, /usr, /lib, /lib64, /nix, this mounts
/// a minimal, purpose-built root filesystem. Suitable for production services.
pub fn bind_mount_rootfs(root: &Path, rootfs_path: &Path) -> Result<()> {
    info!(
        "Bind mounting production rootfs {:?} into container {:?}",
        rootfs_path, root
    );

    if std::fs::symlink_metadata(rootfs_path).is_err() {
        return Err(NucleusError::FilesystemError(format!(
            "Rootfs path does not exist: {:?}",
            rootfs_path
        )));
    }

    // Bind mount the rootfs contents into the container root.
    // The rootfs is expected to contain a standard FHS layout (/bin, /lib, /etc, etc.)
    // produced by a Nix buildEnv or similar.
    let subdirs = ["bin", "sbin", "lib", "lib64", "usr", "etc", "nix"];

    for subdir in &subdirs {
        let source = rootfs_path.join(subdir);
        if !source.exists() {
            debug!("Rootfs subdir {} not present, skipping", subdir);
            continue;
        }
        let source = std::fs::canonicalize(&source).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to canonicalize rootfs mount source {:?}: {}",
                source, e
            ))
        })?;

        let target = root.join(subdir);
        std::fs::create_dir_all(&target).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to create mount point {:?}: {}",
                target, e
            ))
        })?;

        mount(
            Some(&source),
            &target,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to bind mount rootfs {:?} -> {:?}: {}",
                source, target, e
            ))
        })?;

        // Remount read-only
        mount(
            None::<&str>,
            &target,
            None::<&str>,
            MsFlags::MS_REMOUNT
                | MsFlags::MS_BIND
                | MsFlags::MS_RDONLY
                | MsFlags::MS_REC
                | MsFlags::MS_NOSUID
                | MsFlags::MS_NODEV,
            None::<&str>,
        )
        .map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to remount rootfs {:?} read-only: {}",
                target, e
            ))
        })?;

        info!("Mounted rootfs/{} read-only", subdir);
    }

    bind_mount_rootfs_store_paths(root, rootfs_path)?;

    Ok(())
}

/// Mount a pre-built rootfs through overlayfs with a persistent writable upperdir.
///
/// The lowerdir is the Nix-built rootfs. Individual `/nix/store/<hash>-name`
/// paths are re-bound read-only after the overlay mount, preserving the same
/// store-object validation as `bind_mount_rootfs`.
pub fn overlay_mount_rootfs(
    root: &Path,
    rootfs_path: &Path,
    upperdir: &Path,
    workdir: &Path,
) -> Result<()> {
    info!(
        "Overlay mounting rootfs {:?} into container {:?} (upper={:?}, work={:?})",
        rootfs_path, root, upperdir, workdir
    );

    let lowerdir = validate_overlay_mount_dir(rootfs_path, "rootfs lowerdir")?;
    let upperdir = validate_overlay_mount_dir(upperdir, "rootfs overlay upperdir")?;
    let workdir = validate_overlay_mount_dir(workdir, "rootfs overlay workdir")?;
    validate_overlay_mount_dir(root, "container root")?;

    let options = format!(
        "lowerdir={},upperdir={},workdir={}",
        overlay_option_path(&lowerdir, "rootfs lowerdir")?,
        overlay_option_path(&upperdir, "rootfs overlay upperdir")?,
        overlay_option_path(&workdir, "rootfs overlay workdir")?
    );

    mount(
        Some("overlay"),
        root,
        Some("overlay"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(options.as_str()),
    )
    .map_err(|e| {
        NucleusError::FilesystemError(format!(
            "Failed to overlay mount rootfs {:?} -> {:?}: {}",
            lowerdir, root, e
        ))
    })?;

    bind_mount_rootfs_store_paths(root, rootfs_path)?;

    Ok(())
}

fn validate_overlay_mount_dir(path: &Path, label: &str) -> Result<PathBuf> {
    let metadata = std::fs::symlink_metadata(path).map_err(|e| {
        NucleusError::FilesystemError(format!("Failed to stat {} {:?}: {}", label, path, e))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(NucleusError::FilesystemError(format!(
            "{} must not be a symlink: {:?}",
            label, path
        )));
    }
    if !metadata.is_dir() {
        return Err(NucleusError::FilesystemError(format!(
            "{} must be a directory: {:?}",
            label, path
        )));
    }
    std::fs::canonicalize(path).map_err(|e| {
        NucleusError::FilesystemError(format!(
            "Failed to canonicalize {} {:?}: {}",
            label, path, e
        ))
    })
}

fn overlay_option_path(path: &Path, label: &str) -> Result<String> {
    let rendered = path.to_str().ok_or_else(|| {
        NucleusError::FilesystemError(format!("{} path is not valid UTF-8: {:?}", label, path))
    })?;
    if rendered.contains(',') || rendered.contains(':') {
        return Err(NucleusError::FilesystemError(format!(
            "{} path contains a character unsupported in overlay mount options: {}",
            label, rendered
        )));
    }
    Ok(rendered.to_string())
}

fn bind_mount_rootfs_store_paths(root: &Path, rootfs_path: &Path) -> Result<()> {
    let store_paths_file = rootfs_path.join(ROOTFS_STORE_PATHS_FILE);
    if !store_paths_file.exists() {
        return Ok(());
    }

    let content = std::fs::read_to_string(&store_paths_file).map_err(|e| {
        NucleusError::FilesystemError(format!(
            "Failed to read rootfs store paths {:?}: {}",
            store_paths_file, e
        ))
    })?;

    for (line_no, line) in content.lines().enumerate() {
        let source = line.trim();
        if source.is_empty() {
            continue;
        }
        let source = Path::new(source);
        if !is_immediate_nix_store_object_path(source) {
            return Err(NucleusError::FilesystemError(format!(
                "Invalid rootfs store path on line {} in {:?}: {} (expected immediate /nix/store/<32-char-hash>-<name> object)",
                line_no + 1,
                store_paths_file,
                source.display()
            )));
        }
        let store_name = source.file_name().ok_or_else(|| {
            NucleusError::FilesystemError(format!(
                "Invalid rootfs store path on line {} in {:?}: {}",
                line_no + 1,
                store_paths_file,
                source.display()
            ))
        })?;
        let source = std::fs::canonicalize(source).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to canonicalize rootfs store path {:?}: {}",
                source, e
            ))
        })?;
        if !is_immediate_nix_store_object_path(&source) {
            return Err(NucleusError::FilesystemError(format!(
                "Rootfs store path must resolve to an immediate /nix/store/<32-char-hash>-<name> object: {}",
                source.display()
            )));
        }

        let target = root.join("nix/store").join(store_name);
        std::fs::create_dir_all(&target).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to create rootfs store mount point {:?}: {}",
                target, e
            ))
        })?;

        mount(
            Some(&source),
            &target,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to bind mount rootfs store path {:?} -> {:?}: {}",
                source, target, e
            ))
        })?;

        mount(
            None::<&str>,
            &target,
            None::<&str>,
            MsFlags::MS_REMOUNT
                | MsFlags::MS_BIND
                | MsFlags::MS_RDONLY
                | MsFlags::MS_REC
                | MsFlags::MS_NOSUID
                | MsFlags::MS_NODEV,
            None::<&str>,
        )
        .map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to remount rootfs store path {:?} read-only: {}",
                target, e
            ))
        })?;
    }

    Ok(())
}

/// Bind mount essential host directories into container
///
/// This allows host binaries to be accessible inside the container.
/// Used in agent mode. Production mode should use bind_mount_rootfs() instead.
pub fn bind_mount_host_paths(root: &Path, best_effort: bool) -> Result<()> {
    info!("Bind mounting host paths into container");

    // Essential paths to bind mount (read-only)
    let host_paths = vec![
        "/bin", "/usr", "/lib", "/lib64", "/nix", // For NixOS
    ];

    for host_path in host_paths {
        let host = Path::new(host_path);

        // Only mount if the path exists on the host
        if !host.exists() {
            debug!("Skipping {} (not present on host)", host_path);
            continue;
        }

        let container_path = root.join(host_path.trim_start_matches('/'));

        // Create mount point
        if let Err(e) = std::fs::create_dir_all(&container_path) {
            if best_effort {
                warn!("Failed to create mount point {:?}: {}", container_path, e);
                continue;
            }
            return Err(NucleusError::FilesystemError(format!(
                "Failed to create mount point {:?}: {}",
                container_path, e
            )));
        }

        // Attempt bind mount
        // Note: Linux ignores MS_RDONLY on the initial bind mount call.
        // A second remount is required to actually enforce read-only.
        match mount(
            Some(host),
            &container_path,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        ) {
            Ok(_) => {
                // Remount as read-only – required because MS_RDONLY is ignored on initial bind
                mount(
                    None::<&str>,
                    &container_path,
                    None::<&str>,
                    MsFlags::MS_REMOUNT
                        | MsFlags::MS_BIND
                        | MsFlags::MS_RDONLY
                        | MsFlags::MS_REC
                        | MsFlags::MS_NOSUID
                        | MsFlags::MS_NODEV,
                    None::<&str>,
                )
                .map_err(|e| {
                    NucleusError::FilesystemError(format!(
                        "Failed to remount {} as read-only: {}",
                        host_path, e
                    ))
                })?;
                info!(
                    "Bind mounted {} to {:?} (read-only)",
                    host_path, container_path
                );
            }
            Err(e) => {
                if best_effort {
                    warn!(
                        "Failed to bind mount {}: {} (continuing anyway)",
                        host_path, e
                    );
                } else {
                    return Err(NucleusError::FilesystemError(format!(
                        "Failed to bind mount {}: {}",
                        host_path, e
                    )));
                }
            }
        }
    }

    Ok(())
}

/// H7: Sensitive host paths that must not be bind-mounted into containers.
const DENIED_BIND_MOUNT_SOURCES_EXACT: &[&str] = &["/"];

/// Sensitive host subtrees that must not be exposed to a container at all.
const DENIED_BIND_MOUNT_SOURCE_PREFIXES: &[&str] = &[
    "/boot", "/dev", "/etc", "/home", "/proc", "/root", "/run", "/sys", "/var/log", "/var/run",
];

/// Sensitive host paths still denied for explicit provider config mounts.
///
/// Provider config mounts intentionally allow specific host-home credential
/// directories (for example `$HOME/.aws`) that generic volumes reject, but they
/// must not become a broad host filesystem escape hatch.
const DENIED_PROVIDER_CONFIG_SOURCE_EXACT: &[&str] = &["/", "/home", "/root"];

const DENIED_PROVIDER_CONFIG_SOURCE_PREFIXES: &[&str] = &[
    "/boot", "/dev", "/etc", "/proc", "/run", "/sys", "/var/log", "/var/run",
];

/// Container destinations where user-supplied volumes must not be mounted.
///
/// These paths carry trusted runtime/rootfs state. Allowing a volume over them
/// would let a caller replace attested container contents or pseudo-filesystems
/// after validation has completed.
const RESERVED_VOLUME_DESTINATION_PREFIXES: &[&str] = &[
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/lib",
    "/lib64",
    "/nix",
    "/proc",
    "/run/secrets",
    "/sbin",
    "/sys",
    "/usr",
];

fn normalize_bind_mount_source_for_policy(source: &Path) -> Result<PathBuf> {
    if !source.is_absolute() {
        return Err(NucleusError::ConfigError(format!(
            "Bind mount source must be absolute: {:?}",
            source
        )));
    }

    let mut normalized = PathBuf::from("/");

    for component in source.components() {
        match component {
            Component::RootDir => {}
            Component::CurDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir => {
                normalized.pop();
                if normalized.as_os_str().is_empty() {
                    normalized.push("/");
                }
            }
            Component::Prefix(_) => {
                return Err(NucleusError::ConfigError(format!(
                    "Unsupported bind mount source prefix: {:?}",
                    source
                )));
            }
        }
    }

    Ok(normalized)
}

fn reject_denied_bind_mount_source(source: &Path) -> Result<()> {
    for denied in DENIED_BIND_MOUNT_SOURCES_EXACT {
        if source == Path::new(denied) {
            return Err(NucleusError::ConfigError(format!(
                "Bind mount source '{}' is a sensitive host path and cannot be mounted into containers",
                source.display()
            )));
        }
    }

    for denied in DENIED_BIND_MOUNT_SOURCE_PREFIXES {
        let denied_path = Path::new(denied);
        if source == denied_path || source.starts_with(denied_path) {
            return Err(NucleusError::ConfigError(format!(
                "Bind mount source '{}' is under sensitive host path '{}' and cannot be mounted into containers",
                source.display(),
                denied
            )));
        }
    }

    Ok(())
}

fn reject_denied_provider_config_source(source: &Path) -> Result<()> {
    for denied in DENIED_PROVIDER_CONFIG_SOURCE_EXACT {
        if source == Path::new(denied) {
            return Err(NucleusError::ConfigError(format!(
                "Provider config source '{}' is too broad; mount a specific provider config file or directory",
                source.display()
            )));
        }
    }

    if source.parent() == Some(Path::new("/home")) {
        return Err(NucleusError::ConfigError(format!(
            "Provider config source '{}' is a whole host home directory; mount a specific provider config subdirectory",
            source.display()
        )));
    }

    for denied in DENIED_PROVIDER_CONFIG_SOURCE_PREFIXES {
        let denied_path = Path::new(denied);
        if source == denied_path || source.starts_with(denied_path) {
            return Err(NucleusError::ConfigError(format!(
                "Provider config source '{}' is under sensitive host path '{}' and cannot be mounted into containers",
                source.display(),
                denied
            )));
        }
    }

    Ok(())
}

/// Validate bind-mount source policy without requiring the source to exist.
///
/// Topology persistent volumes use this before creating missing host paths, so
/// sensitive host locations are rejected before any mkdir/chown side effects.
pub fn validate_bind_mount_source_policy(source: &Path) -> Result<PathBuf> {
    let normalized = normalize_bind_mount_source_for_policy(source)?;
    reject_denied_bind_mount_source(&normalized)?;
    Ok(normalized)
}

/// Validate that a bind mount source exists and is not a sensitive host path or subtree.
pub fn validate_bind_mount_source(source: &Path) -> Result<()> {
    validate_bind_mount_source_policy(source)?;

    let canonical = std::fs::canonicalize(source).map_err(|e| {
        NucleusError::ConfigError(format!(
            "Failed to resolve bind mount source {:?}: {}",
            source, e
        ))
    })?;
    reject_denied_bind_mount_source(&canonical)
}

/// Validate that an explicit provider config mount source exists and is narrow.
pub fn validate_provider_config_source(source: &Path) -> Result<()> {
    normalize_bind_mount_source_for_policy(source)?;

    let canonical = std::fs::canonicalize(source).map_err(|e| {
        NucleusError::ConfigError(format!(
            "Failed to resolve provider config source {:?}: {}",
            source, e
        ))
    })?;
    let metadata = std::fs::metadata(&canonical).map_err(|e| {
        NucleusError::ConfigError(format!(
            "Failed to stat provider config source {:?}: {}",
            canonical, e
        ))
    })?;
    if !metadata.is_file() && !metadata.is_dir() {
        return Err(NucleusError::ConfigError(format!(
            "Provider config source '{}' must be a regular file or directory",
            canonical.display()
        )));
    }

    reject_denied_provider_config_source(&canonical)
}

fn reject_reserved_volume_destination(dest: &Path) -> Result<()> {
    for reserved in RESERVED_VOLUME_DESTINATION_PREFIXES {
        let reserved_path = Path::new(reserved);
        if dest == reserved_path || dest.starts_with(reserved_path) {
            return Err(NucleusError::ConfigError(format!(
                "Volume destination '{}' is reserved for trusted container/runtime paths and cannot be overlaid",
                dest.display()
            )));
        }
    }

    Ok(())
}

/// Normalize and validate a user-supplied volume destination inside the container.
pub fn normalize_volume_destination(dest: &Path) -> Result<PathBuf> {
    let normalized = normalize_container_destination(dest)?;
    reject_reserved_volume_destination(&normalized)?;
    Ok(normalized)
}

/// Normalize a provider config destination under the configured container home.
///
/// Absolute destinations must already be under `home`. Relative destinations
/// are resolved against `home`. The selected destination may not be the home
/// root itself; provider config mounts must target a file or subdirectory.
pub fn normalize_provider_config_destination(home: &Path, dest: &Path) -> Result<PathBuf> {
    let home = normalize_container_destination(home)?;
    let candidate = if dest.is_absolute() {
        normalize_container_destination(dest)?
    } else {
        let mut relative = PathBuf::new();
        for component in dest.components() {
            match component {
                Component::CurDir => {}
                Component::Normal(part) => relative.push(part),
                Component::ParentDir => {
                    return Err(NucleusError::ConfigError(format!(
                        "Provider config destination must not contain parent traversal: {:?}",
                        dest
                    )));
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err(NucleusError::ConfigError(format!(
                        "Unsupported provider config destination: {:?}",
                        dest
                    )));
                }
            }
        }
        if relative.as_os_str().is_empty() {
            return Err(NucleusError::ConfigError(format!(
                "Provider config destination must not be empty: {:?}",
                dest
            )));
        }
        normalize_container_destination(&home.join(relative))?
    };

    if candidate == home || !candidate.starts_with(&home) {
        return Err(NucleusError::ConfigError(format!(
            "Provider config destination '{}' must be under configured home '{}'",
            candidate.display(),
            home.display()
        )));
    }

    Ok(candidate)
}

/// Resolve a validated user-supplied volume destination under a host-side root directory.
pub fn resolve_volume_destination(root: &Path, dest: &Path) -> Result<PathBuf> {
    let normalized = normalize_volume_destination(dest)?;
    let relative = normalized.strip_prefix("/").map_err(|_| {
        NucleusError::ConfigError(format!(
            "Volume destination is not absolute after normalization: {:?}",
            normalized
        ))
    })?;
    Ok(root.join(relative))
}

/// Mount persistent bind volumes and ephemeral tmpfs volumes into the container root.
pub fn mount_volumes(root: &Path, volumes: &[crate::container::VolumeMount]) -> Result<()> {
    use crate::container::VolumeSource;

    if volumes.is_empty() {
        return Ok(());
    }

    info!("Mounting {} volume(s) into container", volumes.len());

    for volume in volumes {
        let dest = resolve_volume_destination(root, &volume.dest)?;

        match &volume.source {
            VolumeSource::Bind { source } => {
                // H7: Deny bind-mounting sensitive host paths
                validate_bind_mount_source(source)?;

                // Use symlink_metadata (lstat) instead of .exists() to avoid
                // following symlinks in the existence check (O_NOFOLLOW semantics).
                if std::fs::symlink_metadata(source).is_err() {
                    return Err(NucleusError::FilesystemError(format!(
                        "Volume source does not exist: {:?}",
                        source
                    )));
                }

                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        NucleusError::FilesystemError(format!(
                            "Failed to create volume mount parent {:?}: {}",
                            parent, e
                        ))
                    })?;
                }

                let recursive = source.is_dir();
                if source.is_file() {
                    std::fs::write(&dest, "").map_err(|e| {
                        NucleusError::FilesystemError(format!(
                            "Failed to create volume mount point {:?}: {}",
                            dest, e
                        ))
                    })?;
                } else {
                    std::fs::create_dir_all(&dest).map_err(|e| {
                        NucleusError::FilesystemError(format!(
                            "Failed to create volume mount dir {:?}: {}",
                            dest, e
                        ))
                    })?;
                }

                let initial_flags = if recursive {
                    MsFlags::MS_BIND | MsFlags::MS_REC
                } else {
                    MsFlags::MS_BIND
                };
                mount(
                    Some(source.as_path()),
                    &dest,
                    None::<&str>,
                    initial_flags,
                    None::<&str>,
                )
                .map_err(|e| {
                    NucleusError::FilesystemError(format!(
                        "Failed to bind mount volume {:?} -> {:?}: {}",
                        source, dest, e
                    ))
                })?;

                let mut remount_flags =
                    MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_NOSUID | MsFlags::MS_NODEV;
                if recursive {
                    remount_flags |= MsFlags::MS_REC;
                }
                if volume.read_only {
                    remount_flags |= MsFlags::MS_RDONLY;
                }

                mount(
                    None::<&str>,
                    &dest,
                    None::<&str>,
                    remount_flags,
                    None::<&str>,
                )
                .map_err(|e| {
                    NucleusError::FilesystemError(format!(
                        "Failed to remount volume {:?} with final flags: {}",
                        dest, e
                    ))
                })?;

                info!(
                    "Mounted bind volume {:?} -> {:?} ({})",
                    source,
                    volume.dest,
                    if volume.read_only { "ro" } else { "rw" }
                );
            }
            VolumeSource::Tmpfs { size } => {
                std::fs::create_dir_all(&dest).map_err(|e| {
                    NucleusError::FilesystemError(format!(
                        "Failed to create tmpfs mount dir {:?}: {}",
                        dest, e
                    ))
                })?;

                // M8: Validate size parameter to prevent option injection.
                // Only allow digits, optionally followed by K/M/G suffix.
                if let Some(value) = size.as_ref() {
                    let valid = value
                        .chars()
                        .all(|c| c.is_ascii_digit() || "kKmMgG".contains(c));
                    if !valid || value.is_empty() {
                        return Err(NucleusError::FilesystemError(format!(
                            "Invalid tmpfs size value '{}': only digits with optional K/M/G suffix allowed",
                            value
                        )));
                    }
                }

                // M7: Default to 64MB instead of half of physical RAM to
                // prevent memory DoS from unbounded tmpfs volumes.
                let mount_data = size
                    .as_ref()
                    .map(|value| format!("size={},mode=0700", value))
                    .unwrap_or_else(|| "size=64M,mode=0700".to_string());

                let mut flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV;
                if volume.read_only {
                    flags |= MsFlags::MS_RDONLY;
                }
                mount(
                    Some("tmpfs"),
                    &dest,
                    Some("tmpfs"),
                    flags,
                    Some(mount_data.as_str()),
                )
                .map_err(|e| {
                    NucleusError::FilesystemError(format!(
                        "Failed to mount tmpfs volume at {:?}: {}",
                        dest, e
                    ))
                })?;

                info!(
                    "Mounted tmpfs volume at {:?}{}{}",
                    volume.dest,
                    size.as_ref()
                        .map(|value| format!(" (size={})", value))
                        .unwrap_or_default(),
                    if volume.read_only { " (ro)" } else { "" }
                );
            }
        }
    }

    Ok(())
}

/// Mount the private sandbox home tmpfs.
pub fn mount_home_tmpfs(
    root: &Path,
    home: &Path,
    identity: &crate::container::ProcessIdentity,
) -> Result<()> {
    let dest = resolve_container_destination(root, home)?;
    std::fs::create_dir_all(&dest).map_err(|e| {
        NucleusError::FilesystemError(format!(
            "Failed to create sandbox home mount dir {:?}: {}",
            dest, e
        ))
    })?;

    let mount_data = format!(
        "size=256M,mode=0700,uid={},gid={}",
        identity.uid, identity.gid
    );
    mount(
        Some("tmpfs"),
        &dest,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        Some(mount_data.as_str()),
    )
    .map_err(|e| {
        NucleusError::FilesystemError(format!(
            "Failed to mount sandbox home tmpfs at {:?}: {}",
            dest, e
        ))
    })?;

    info!("Mounted sandbox home tmpfs at {:?}", home);
    Ok(())
}

/// Mount explicit provider CLI config paths under the sandbox home.
pub fn mount_provider_configs(
    root: &Path,
    home: &Path,
    provider_configs: &[crate::container::ProviderConfigMount],
) -> Result<()> {
    if provider_configs.is_empty() {
        return Ok(());
    }

    info!(
        "Mounting {} provider config path(s) into sandbox home",
        provider_configs.len()
    );

    for provider_config in provider_configs {
        validate_provider_config_source(&provider_config.source)?;
        let canonical_source = std::fs::canonicalize(&provider_config.source).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to canonicalize provider config source {:?}: {}",
                provider_config.source, e
            ))
        })?;
        let metadata = std::fs::metadata(&canonical_source).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to stat provider config source {:?}: {}",
                canonical_source, e
            ))
        })?;
        let container_dest = normalize_provider_config_destination(home, &provider_config.dest)?;
        let dest = resolve_container_destination(root, &container_dest)?;

        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to create provider config parent {:?}: {}",
                    parent, e
                ))
            })?;
        }

        if metadata.is_file() {
            std::fs::write(&dest, "").map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to create provider config mount point {:?}: {}",
                    dest, e
                ))
            })?;
        } else {
            std::fs::create_dir_all(&dest).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to create provider config mount dir {:?}: {}",
                    dest, e
                ))
            })?;
        }

        let recursive = metadata.is_dir();
        let initial_flags = if recursive {
            MsFlags::MS_BIND | MsFlags::MS_REC
        } else {
            MsFlags::MS_BIND
        };
        mount(
            Some(canonical_source.as_path()),
            &dest,
            None::<&str>,
            initial_flags,
            None::<&str>,
        )
        .map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to bind mount provider config {:?} -> {:?}: {}",
                canonical_source, dest, e
            ))
        })?;

        let mut remount_flags = MsFlags::MS_REMOUNT
            | MsFlags::MS_BIND
            | MsFlags::MS_NOSUID
            | MsFlags::MS_NODEV
            | MsFlags::MS_NOEXEC;
        if recursive {
            remount_flags |= MsFlags::MS_REC;
        }
        if provider_config.read_only {
            remount_flags |= MsFlags::MS_RDONLY;
        }

        mount(
            None::<&str>,
            &dest,
            None::<&str>,
            remount_flags,
            None::<&str>,
        )
        .map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to remount provider config {:?} with final flags: {}",
                dest, e
            ))
        })?;

        info!(
            "Mounted provider config {:?} -> {:?} ({})",
            canonical_source,
            container_dest,
            if provider_config.read_only {
                "ro"
            } else {
                "rw"
            }
        );
    }

    Ok(())
}

/// Mount the first-class workspace into the container root.
pub fn mount_workspace(root: &Path, workspace: &crate::container::WorkspaceConfig) -> Result<()> {
    let Some(source) = workspace.effective_host_path() else {
        return Ok(());
    };

    if workspace.mode == crate::container::WorkspaceMode::CopyInOut {
        let metadata = std::fs::symlink_metadata(source).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to stat workspace staging path {:?}: {}",
                source, e
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(NucleusError::FilesystemError(format!(
                "Workspace staging path must be a real directory: {:?}",
                source
            )));
        }
    } else {
        crate::filesystem::validate_workspace_host_path(source)?;
    }
    let dest = resolve_container_destination(root, &workspace.container_path)?;
    std::fs::create_dir_all(&dest).map_err(|e| {
        NucleusError::FilesystemError(format!(
            "Failed to create workspace mount point {:?}: {}",
            dest, e
        ))
    })?;

    mount(
        Some(source.as_path()),
        &dest,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| {
        NucleusError::FilesystemError(format!(
            "Failed to bind mount workspace {:?} -> {:?}: {}",
            source, dest, e
        ))
    })?;

    let mut remount_flags = MsFlags::MS_REMOUNT
        | MsFlags::MS_BIND
        | MsFlags::MS_REC
        | MsFlags::MS_NOSUID
        | MsFlags::MS_NODEV;
    if workspace.is_read_only() {
        remount_flags |= MsFlags::MS_RDONLY;
    }
    if !workspace.allow_execute {
        remount_flags |= MsFlags::MS_NOEXEC;
    }

    mount(
        None::<&str>,
        &dest,
        None::<&str>,
        remount_flags,
        None::<&str>,
    )
    .map_err(|e| {
        NucleusError::FilesystemError(format!(
            "Failed to remount workspace {:?} with final flags: {}",
            dest, e
        ))
    })?;

    info!(
        "Mounted workspace {:?} -> {:?} (mode={:?}, exec={})",
        source, workspace.container_path, workspace.mode, workspace.allow_execute
    );

    Ok(())
}

/// Mount procfs at the given path
///
/// In rootless mode, procfs mounting should work due to user namespace capabilities.
/// When `hide_pids` is true, mounts with hidepid=2 so processes cannot enumerate
/// other PIDs (production hardening). The best-effort fallback only applies to
/// non-hardened procfs mounts; requested hidepid hardening is fail-closed.
pub fn mount_procfs(
    proc_path: &Path,
    best_effort: bool,
    read_only: bool,
    hide_pids: bool,
) -> Result<()> {
    info!(
        "Mounting procfs at {:?} (hidepid={})",
        proc_path,
        if hide_pids { "2" } else { "0" }
    );

    let mount_data: Option<&str> = if hide_pids { Some("hidepid=2") } else { None };

    let mounted = match mount(
        Some("proc"),
        proc_path,
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        mount_data,
    ) {
        Ok(_) => true,
        Err(e) => handle_procfs_mount_failure(e, best_effort, hide_pids)?,
    };

    if mounted {
        if read_only {
            mount(
                None::<&str>,
                proc_path,
                None::<&str>,
                MsFlags::MS_REMOUNT
                    | MsFlags::MS_RDONLY
                    | MsFlags::MS_NOSUID
                    | MsFlags::MS_NODEV
                    | MsFlags::MS_NOEXEC,
                mount_data,
            )
            .map_err(|e| {
                NucleusError::FilesystemError(format!("Failed to remount procfs read-only: {}", e))
            })?;
            info!("Successfully mounted procfs (read-only)");
        } else {
            info!("Successfully mounted procfs");
        }
    }

    Ok(())
}

fn handle_procfs_mount_failure(
    e: nix::errno::Errno,
    best_effort: bool,
    hide_pids: bool,
) -> Result<bool> {
    if hide_pids {
        return Err(NucleusError::FilesystemError(format!(
            "Failed to mount procfs with required hidepid=2: {}",
            e
        )));
    }

    if best_effort {
        warn!("Failed to mount procfs: {} (continuing anyway)", e);
        Ok(false)
    } else {
        Err(NucleusError::FilesystemError(format!(
            "Failed to mount procfs: {}",
            e
        )))
    }
}

/// Paths to mask with /dev/null (files) – matches OCI runtime spec masked paths.
/// Exposed for testing; the canonical list of sensitive /proc entries that must
/// be hidden from container processes.
pub const PROC_NULL_MASKED: &[&str] = &[
    "kallsyms",
    "kcore",
    "sched_debug",
    "timer_list",
    "timer_stats",
    "keys",
    "latency_stats",
    "config.gz",
    "sysrq-trigger",
    "kpagecount",
    "kpageflags",
    "kpagecgroup",
];

/// Paths to remount read-only – matches OCI runtime spec readonlyPaths.
pub const PROC_READONLY_PATHS: &[&str] = &["bus", "fs", "irq", "sys"];

/// Paths to mask with empty tmpfs (directories).
pub const PROC_TMPFS_MASKED: &[&str] = &["acpi", "scsi"];

fn remount_proc_path_readonly(target: &Path) -> Result<()> {
    mount(
        Some(target),
        target,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| {
        NucleusError::FilesystemError(format!(
            "Failed to bind-mount {:?} onto itself for read-only remount: {}",
            target, e
        ))
    })?;

    mount(
        None::<&str>,
        target,
        None::<&str>,
        MsFlags::MS_REMOUNT
            | MsFlags::MS_BIND
            | MsFlags::MS_RDONLY
            | MsFlags::MS_NOSUID
            | MsFlags::MS_NODEV
            | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .map_err(|e| {
        NucleusError::FilesystemError(format!("Failed to remount {:?} read-only: {}", target, e))
    })?;

    Ok(())
}

/// Mask sensitive /proc paths by bind-mounting /dev/null or tmpfs over them
///
/// This reduces kernel information leakage from the container. Follows OCI runtime
/// conventions for masked paths.
///
/// SEC-06: When `production` is true, failures to mask critical paths
/// (kcore, kallsyms, sysrq-trigger) are fatal instead of warn-and-continue.
pub fn mask_proc_paths(proc_path: &Path, production: bool) -> Result<()> {
    info!("Masking sensitive /proc paths");

    const CRITICAL_PROC_PATHS: &[&str] = &["kcore", "kallsyms", "sysrq-trigger"];

    for name in PROC_READONLY_PATHS {
        let target = proc_path.join(name);
        if !target.exists() {
            continue;
        }
        match remount_proc_path_readonly(&target) {
            Ok(_) => debug!("Remounted /proc/{} read-only", name),
            Err(e) => {
                if production {
                    return Err(NucleusError::FilesystemError(format!(
                        "Failed to remount /proc/{} read-only in production mode: {}",
                        name, e
                    )));
                }
                warn!(
                    "Failed to remount /proc/{} read-only: {} (continuing)",
                    name, e
                );
            }
        }
    }

    let dev_null = Path::new("/dev/null");

    for name in PROC_NULL_MASKED {
        let target = proc_path.join(name);
        if !target.exists() {
            continue;
        }
        match mount(
            Some(dev_null),
            &target,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        ) {
            Ok(_) => {
                // Remount read-only: Linux ignores MS_RDONLY on the initial bind mount,
                // so a separate MS_REMOUNT|MS_BIND|MS_RDONLY call is required.
                if let Err(e) = mount(
                    None::<&str>,
                    &target,
                    None::<&str>,
                    MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                    None::<&str>,
                ) {
                    if production && CRITICAL_PROC_PATHS.contains(name) {
                        return Err(NucleusError::FilesystemError(format!(
                            "Failed to remount /proc/{} read-only in production mode: {}",
                            name, e
                        )));
                    }
                    warn!(
                        "Failed to remount /proc/{} read-only: {} (continuing)",
                        name, e
                    );
                }
                debug!("Masked /proc/{} (read-only)", name);
            }
            Err(e) => {
                if production && CRITICAL_PROC_PATHS.contains(name) {
                    return Err(NucleusError::FilesystemError(format!(
                        "Failed to mask critical /proc/{} in production mode: {}",
                        name, e
                    )));
                }
                warn!("Failed to mask /proc/{}: {} (continuing)", name, e);
            }
        }
    }

    for name in PROC_TMPFS_MASKED {
        let target = proc_path.join(name);
        if !target.exists() {
            continue;
        }
        match mount(
            Some("tmpfs"),
            &target,
            Some("tmpfs"),
            MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
            Some("size=0"),
        ) {
            Ok(_) => debug!("Masked /proc/{}", name),
            Err(e) => {
                if production {
                    return Err(NucleusError::FilesystemError(format!(
                        "Failed to mask /proc/{} in production mode: {}",
                        name, e
                    )));
                }
                warn!("Failed to mask /proc/{}: {} (continuing)", name, e);
            }
        }
    }

    info!("Finished masking sensitive /proc paths");
    Ok(())
}

/// Switch to new root filesystem using pivot_root or chroot
///
/// This implements the transition: populated -> pivoted
/// Fails closed if root switching cannot be established.
pub fn switch_root(new_root: &Path, allow_chroot_fallback: bool) -> Result<()> {
    info!("Switching root to {:?}", new_root);

    match pivot_root_impl(new_root) {
        Ok(()) => {
            info!("Successfully switched root using pivot_root");
            Ok(())
        }
        Err(e) => {
            if allow_chroot_fallback {
                warn!(
                    "pivot_root failed ({}), falling back to chroot due to explicit \
                     configuration",
                    e
                );
                chroot_impl(new_root)
            } else {
                Err(NucleusError::PivotRootError(format!(
                    "pivot_root failed: {}. chroot fallback is disabled by default; use \
                     --allow-chroot-fallback to allow weaker isolation",
                    e
                )))
            }
        }
    }
}

/// Implement root switch using pivot_root(2)
///
/// pivot_root is preferred over chroot because:
/// - More secure (old root can be unmounted)
/// - Works better with mount namespaces
fn pivot_root_impl(new_root: &Path) -> Result<()> {
    use nix::unistd::pivot_root;

    // pivot_root requires new_root to be a mount point
    // and old_root to be under new_root

    let old_root = new_root.join(".old_root");
    std::fs::create_dir_all(&old_root).map_err(|e| {
        NucleusError::PivotRootError(format!("Failed to create old_root directory: {}", e))
    })?;

    // Perform pivot_root
    pivot_root(new_root, &old_root)
        .map_err(|e| NucleusError::PivotRootError(format!("pivot_root syscall failed: {}", e)))?;

    // Change to new root
    std::env::set_current_dir("/")
        .map_err(|e| NucleusError::PivotRootError(format!("Failed to chdir to /: {}", e)))?;

    // Unmount old root
    nix::mount::umount2("/.old_root", nix::mount::MntFlags::MNT_DETACH)
        .map_err(|e| NucleusError::PivotRootError(format!("Failed to unmount old root: {}", e)))?;

    // Remove old root directory
    let _ = std::fs::remove_dir("/.old_root");

    Ok(())
}

/// Implement root switch using chroot(2)
///
/// chroot is less secure than pivot_root but works in more situations
fn chroot_impl(new_root: &Path) -> Result<()> {
    fn close_non_stdio_fds_after_chroot() -> Result<()> {
        // Any pre-chroot fd can still reach outside the jail, so close every
        // non-stdio descriptor before continuing setup inside the fallback root.
        let ret = unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) };
        if ret == 0 {
            return Ok(());
        }

        let max_fd = match unsafe { libc::sysconf(libc::_SC_OPEN_MAX) } {
            n if n > 3 && n <= i32::MAX as libc::c_long => n as i32,
            _ => 1024,
        };

        for fd in 3..max_fd {
            if unsafe { libc::close(fd) } != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EBADF) {
                    return Err(NucleusError::PivotRootError(format!(
                        "Failed to close inherited fd {} after chroot: {}",
                        fd, err
                    )));
                }
            }
        }

        Ok(())
    }

    chroot(new_root)
        .map_err(|e| NucleusError::PivotRootError(format!("chroot syscall failed: {}", e)))?;

    // Change to new root
    std::env::set_current_dir("/")
        .map_err(|e| NucleusError::PivotRootError(format!("Failed to chdir to /: {}", e)))?;

    close_non_stdio_fds_after_chroot()?;

    // L3: Drop CAP_SYS_CHROOT after chroot to prevent escape via nested chroot.
    if let Err(e) = caps::drop(
        None,
        caps::CapSet::Bounding,
        caps::Capability::CAP_SYS_CHROOT,
    ) {
        debug!(
            "Could not drop CAP_SYS_CHROOT after chroot: {} (may not be present)",
            e
        );
    }
    if let Err(e) = caps::drop(
        None,
        caps::CapSet::Effective,
        caps::Capability::CAP_SYS_CHROOT,
    ) {
        debug!(
            "Could not drop effective CAP_SYS_CHROOT: {} (may not be present)",
            e
        );
    }
    if let Err(e) = caps::drop(
        None,
        caps::CapSet::Permitted,
        caps::Capability::CAP_SYS_CHROOT,
    ) {
        debug!(
            "Could not drop permitted CAP_SYS_CHROOT: {} (may not be present)",
            e
        );
    }

    info!("Successfully switched root using chroot (CAP_SYS_CHROOT dropped)");

    Ok(())
}

/// Mount secret files into the container root.
///
/// Each secret is bind-mounted read-only from its source to the destination
/// path inside the container. Intermediate directories are created as needed.
pub fn mount_secrets(root: &Path, secrets: &[crate::container::SecretMount]) -> Result<()> {
    if secrets.is_empty() {
        return Ok(());
    }

    info!("Mounting {} secret(s) into container", secrets.len());

    for secret in secrets {
        let source_fd = open(
            &secret.source,
            OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to open secret source {:?} with O_NOFOLLOW: {}",
                secret.source, e
            ))
        })?;
        let source_stat = fstat(&source_fd).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to stat secret source {:?}: {}",
                secret.source, e
            ))
        })?;
        let source_kind = SFlag::from_bits_truncate(source_stat.st_mode);
        let source_is_file = source_kind == SFlag::S_IFREG;
        let source_is_dir = source_kind == SFlag::S_IFDIR;
        if !source_is_file && !source_is_dir {
            return Err(NucleusError::FilesystemError(format!(
                "Secret source {:?} must be a regular file or directory",
                secret.source
            )));
        }
        let source_fd_path = PathBuf::from(format!("/proc/self/fd/{}", source_fd.as_raw_fd()));

        // Destination inside container root
        let dest = resolve_container_destination(root, &secret.dest)?;

        // Create parent directories
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to create secret mount parent {:?}: {}",
                    parent, e
                ))
            })?;
        }

        // Create mount point file
        if source_is_file {
            std::fs::write(&dest, "").map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to create secret mount point {:?}: {}",
                    dest, e
                ))
            })?;
        } else {
            std::fs::create_dir_all(&dest).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to create secret mount dir {:?}: {}",
                    dest, e
                ))
            })?;
        }

        // Bind mount read-only
        mount(
            Some(source_fd_path.as_path()),
            &dest,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to bind mount secret {:?}: {}",
                secret.source, e
            ))
        })?;

        mount(
            None::<&str>,
            &dest,
            None::<&str>,
            MsFlags::MS_REMOUNT
                | MsFlags::MS_BIND
                | MsFlags::MS_RDONLY
                | MsFlags::MS_NOSUID
                | MsFlags::MS_NODEV
                | MsFlags::MS_NOEXEC,
            None::<&str>,
        )
        .map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to remount secret {:?} read-only: {}",
                dest, e
            ))
        })?;

        // Apply configured file permissions on the mount point
        if source_is_file {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(secret.mode);
            if let Err(e) = std::fs::set_permissions(&dest, perms) {
                warn!(
                    "Failed to set mode {:04o} on secret {:?}: {} (bind mount may override)",
                    secret.mode, dest, e
                );
            }
        }

        debug!(
            "Mounted secret {:?} -> {:?} (mode {:04o})",
            secret.source, secret.dest, secret.mode
        );
    }

    Ok(())
}

/// Mount secrets onto a dedicated in-memory tmpfs instead of bind-mounting host paths.
///
/// Creates a per-container tmpfs at `<root>/run/secrets` with MS_NOEXEC | MS_NOSUID | MS_NODEV,
/// copies secret contents into it, then zeros the read buffer. This ensures secrets
/// never reference host-side files after setup and are never persisted to disk.
pub fn mount_secrets_inmemory(
    root: &Path,
    secrets: &[crate::container::SecretMount],
    identity: &crate::container::ProcessIdentity,
) -> Result<()> {
    if secrets.is_empty() {
        return Ok(());
    }

    info!("Mounting {} secret(s) on in-memory tmpfs", secrets.len());

    let secrets_dir = root.join("run/secrets");
    std::fs::create_dir_all(&secrets_dir).map_err(|e| {
        NucleusError::FilesystemError(format!(
            "Failed to create secrets dir {:?}: {}",
            secrets_dir, e
        ))
    })?;

    // Mount a size-limited tmpfs for secrets (16 MiB max)
    if let Err(e) = mount(
        Some("tmpfs"),
        &secrets_dir,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        Some("size=16m,mode=0700"),
    ) {
        let _ = std::fs::remove_dir_all(&secrets_dir);
        return Err(NucleusError::FilesystemError(format!(
            "Failed to mount secrets tmpfs at {:?}: {}",
            secrets_dir, e
        )));
    }

    if !identity.is_root() {
        nix::unistd::chown(
            &secrets_dir,
            Some(nix::unistd::Uid::from_raw(identity.uid)),
            Some(nix::unistd::Gid::from_raw(identity.gid)),
        )
        .map_err(|e| {
            let _ = nix::mount::umount2(&secrets_dir, nix::mount::MntFlags::MNT_DETACH);
            let _ = std::fs::remove_dir_all(&secrets_dir);
            NucleusError::FilesystemError(format!(
                "Failed to set /run/secrets owner to {}:{}: {}",
                identity.uid, identity.gid, e
            ))
        })?;
    }

    // Rollback: unmount tmpfs and remove dir if any secret fails
    let result = mount_secrets_inmemory_inner(&secrets_dir, root, secrets, identity);
    if let Err(ref e) = result {
        let _ = nix::mount::umount2(&secrets_dir, nix::mount::MntFlags::MNT_DETACH);
        let _ = std::fs::remove_dir_all(&secrets_dir);
        return Err(NucleusError::FilesystemError(format!(
            "Secret mount failed (rolled back): {}",
            e
        )));
    }

    info!("All secrets mounted on in-memory tmpfs");
    Ok(())
}

fn mount_secrets_inmemory_inner(
    secrets_dir: &Path,
    root: &Path,
    secrets: &[crate::container::SecretMount],
    identity: &crate::container::ProcessIdentity,
) -> Result<()> {
    for secret in secrets {
        let mut content = read_regular_file_nofollow(&secret.source)?;

        // Determine destination path inside the secrets tmpfs
        let dest = resolve_container_destination(secrets_dir, &secret.dest)?;

        // Create parent directories within the tmpfs
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to create secret parent dir {:?}: {}",
                    parent, e
                ))
            })?;
        }

        // Write secret content to tmpfs
        std::fs::write(&dest, &content).map_err(|e| {
            NucleusError::FilesystemError(format!("Failed to write secret to {:?}: {}", dest, e))
        })?;

        // Set permissions
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(secret.mode);
            std::fs::set_permissions(&dest, perms).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to set permissions on secret {:?}: {}",
                    dest, e
                ))
            })?;
        }

        if !identity.is_root() {
            nix::unistd::chown(
                &dest,
                Some(nix::unistd::Uid::from_raw(identity.uid)),
                Some(nix::unistd::Gid::from_raw(identity.gid)),
            )
            .map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to set permissions owner on secret {:?} to {}:{}: {}",
                    dest, identity.uid, identity.gid, e
                ))
            })?;
        }

        // Zero the in-memory buffer
        zeroize::Zeroize::zeroize(&mut content);
        drop(content);

        // Also bind-mount the secret to its expected container path for compatibility
        let container_dest = resolve_container_destination(root, &secret.dest)?;
        if container_dest != dest {
            if let Some(parent) = container_dest.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    NucleusError::FilesystemError(format!(
                        "Failed to create secret mount parent {:?}: {}",
                        parent, e
                    ))
                })?;
            }

            std::fs::write(&container_dest, "").map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to create secret mount point {:?}: {}",
                    container_dest, e
                ))
            })?;

            mount(
                Some(dest.as_path()),
                &container_dest,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
            .map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to bind mount secret {:?} -> {:?}: {}",
                    dest, container_dest, e
                ))
            })?;

            mount(
                None::<&str>,
                &container_dest,
                None::<&str>,
                MsFlags::MS_REMOUNT
                    | MsFlags::MS_BIND
                    | MsFlags::MS_RDONLY
                    | MsFlags::MS_NOSUID
                    | MsFlags::MS_NODEV
                    | MsFlags::MS_NOEXEC,
                None::<&str>,
            )
            .map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to remount secret {:?} read-only: {}",
                    container_dest, e
                ))
            })?;
        }

        debug!(
            "Secret {:?} -> {:?} (in-memory tmpfs, mode {:04o})",
            secret.source, secret.dest, secret.mode
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn test_validate_bind_mount_source_rejects_sensitive_subtrees() {
        for path in [
            "/",
            "/boot",
            "/dev/kmsg",
            "/etc",
            "/etc/passwd",
            "/home/alice/.ssh",
            "/proc/sys",
            "/root/.ssh",
            "/run/secrets",
            "/sys/fs/cgroup",
            "/var/log",
        ] {
            let err = validate_bind_mount_source(Path::new(path)).unwrap_err();
            assert!(
                err.to_string().contains("sensitive host path"),
                "expected sensitive-path rejection for {path}, got: {err}"
            );
        }
    }

    #[test]
    fn test_validate_bind_mount_source_allows_regular_host_paths() {
        let temp = tempfile::TempDir::new().unwrap();
        let safe_path = temp.path().join("data");
        std::fs::create_dir(&safe_path).unwrap();

        validate_bind_mount_source(&safe_path).unwrap();
    }

    #[test]
    fn test_validate_provider_config_source_allows_regular_paths() {
        let temp = tempfile::TempDir::new().unwrap();
        let safe_path = temp.path().join("config.json");
        std::fs::write(&safe_path, "{}").unwrap();

        validate_provider_config_source(&safe_path).unwrap();
    }

    #[test]
    fn test_validate_provider_config_source_rejects_sensitive_paths() {
        let err = validate_provider_config_source(Path::new("/etc/passwd")).unwrap_err();
        assert!(
            err.to_string().contains("sensitive host path"),
            "expected sensitive-path rejection, got: {err}"
        );
    }

    #[test]
    fn test_validate_bind_mount_source_normalizes_parent_components_before_filtering() {
        let temp = tempfile::TempDir::new().unwrap();
        let safe_path = temp.path().join("data");
        std::fs::create_dir(&safe_path).unwrap();

        validate_bind_mount_source(&safe_path.join("../data")).unwrap();
    }

    #[test]
    fn test_bind_mount_source_policy_rejects_sensitive_paths_before_creation() {
        let err = validate_bind_mount_source_policy(Path::new("/tmp/../../etc/nucleus-volume"))
            .unwrap_err();
        assert!(
            err.to_string().contains("sensitive host path"),
            "expected sensitive-path rejection before path creation, got: {err}"
        );
    }

    #[test]
    fn test_volume_destinations_reject_reserved_container_paths() {
        for path in [
            "/bin/tool",
            "/dev/null",
            "/etc/app",
            "/lib64/ld-linux-x86-64.so.2",
            "/nix/store/data",
            "/proc/sys",
            "/run/secrets/token",
            "/usr/local/bin",
        ] {
            let err = normalize_volume_destination(Path::new(path)).unwrap_err();
            assert!(
                err.to_string().contains("reserved"),
                "expected reserved destination rejection for {path}, got: {err}"
            );
        }
    }

    #[test]
    fn test_volume_destinations_allow_data_paths() {
        assert_eq!(
            normalize_volume_destination(Path::new("/var/lib/app")).unwrap(),
            PathBuf::from("/var/lib/app")
        );
        assert_eq!(
            normalize_volume_destination(Path::new("/opt/app/data")).unwrap(),
            PathBuf::from("/opt/app/data")
        );
    }

    #[test]
    fn test_provider_config_destination_relative_to_home() {
        assert_eq!(
            normalize_provider_config_destination(
                Path::new("/home/agent"),
                Path::new(".config/provider")
            )
            .unwrap(),
            PathBuf::from("/home/agent/.config/provider")
        );
    }

    #[test]
    fn test_provider_config_destination_rejects_escape() {
        let err =
            normalize_provider_config_destination(Path::new("/home/agent"), Path::new("../.ssh"))
                .unwrap_err();
        assert!(
            err.to_string().contains("parent traversal"),
            "expected traversal rejection, got: {err}"
        );

        let err = normalize_provider_config_destination(
            Path::new("/home/agent"),
            Path::new("/workspace/.aws"),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("must be under configured home"),
            "expected home-boundary rejection, got: {err}"
        );
    }

    #[test]
    fn test_production_rootfs_path_rejects_parent_traversal() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = temp.path().join("store");
        std::fs::create_dir(&store).unwrap();

        let err =
            validate_rootfs_path_under_store(&store.join("../outside-rootfs"), &store).unwrap_err();

        assert!(
            err.to_string().contains("parent traversal"),
            "expected parent traversal rejection, got: {err}"
        );
    }

    #[test]
    fn test_production_rootfs_path_rejects_symlink_escape() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = temp.path().join("store");
        let outside = temp.path().join("outside-rootfs");
        std::fs::create_dir(&store).unwrap();
        std::fs::create_dir(&outside).unwrap();
        symlink(&outside, store.join("rootfs-link")).unwrap();

        let err = validate_rootfs_path_under_store(&store.join("rootfs-link"), &store).unwrap_err();

        assert!(
            err.to_string().contains("resolve under"),
            "expected symlink escape rejection, got: {err}"
        );
    }

    #[test]
    fn test_production_rootfs_path_returns_canonical_store_target() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = temp.path().join("store");
        let rootfs = store.join("abcd-rootfs");
        std::fs::create_dir(&store).unwrap();
        std::fs::create_dir(&rootfs).unwrap();
        symlink(&rootfs, store.join("rootfs-link")).unwrap();

        let canonical =
            validate_rootfs_path_under_store(&store.join("rootfs-link"), &store).unwrap();

        assert_eq!(canonical, std::fs::canonicalize(rootfs).unwrap());
    }

    #[test]
    fn test_agent_toolchain_rootfs_path_allows_non_store_directory() {
        let temp = tempfile::TempDir::new().unwrap();
        let rootfs = temp.path().join("agent-rootfs");
        std::fs::create_dir(&rootfs).unwrap();

        let canonical = validate_agent_toolchain_rootfs_path(&rootfs).unwrap();

        assert_eq!(canonical, std::fs::canonicalize(rootfs).unwrap());
    }

    #[test]
    fn test_agent_toolchain_rootfs_path_rejects_relative_path() {
        let err = validate_agent_toolchain_rootfs_path(Path::new("agent-rootfs")).unwrap_err();

        assert!(
            err.to_string().contains("must be absolute"),
            "expected absolute path rejection, got: {err}"
        );
    }

    #[test]
    fn test_agent_toolchain_rootfs_path_rejects_parent_traversal() {
        let temp = tempfile::TempDir::new().unwrap();
        let err =
            validate_agent_toolchain_rootfs_path(&temp.path().join("../agent-rootfs")).unwrap_err();

        assert!(
            err.to_string().contains("parent traversal"),
            "expected parent traversal rejection, got: {err}"
        );
    }

    #[test]
    fn test_agent_toolchain_rootfs_path_rejects_file() {
        let temp = tempfile::TempDir::new().unwrap();
        let rootfs = temp.path().join("agent-rootfs");
        std::fs::write(&rootfs, "not a directory").unwrap();

        let err = validate_agent_toolchain_rootfs_path(&rootfs).unwrap_err();

        assert!(
            err.to_string().contains("must resolve to a directory"),
            "expected directory rejection, got: {err}"
        );
    }

    #[test]
    fn test_rootfs_store_path_binds_reject_store_root_before_mounting() {
        let temp = tempfile::TempDir::new().unwrap();
        let container_root = temp.path().join("container-root");
        let rootfs = temp.path().join("rootfs");
        std::fs::create_dir_all(&container_root).unwrap();
        std::fs::create_dir_all(&rootfs).unwrap();
        std::fs::write(rootfs.join(ROOTFS_STORE_PATHS_FILE), "/nix/store\n").unwrap();

        let err = bind_mount_rootfs_store_paths(&container_root, &rootfs).unwrap_err();

        assert!(
            err.to_string().contains("expected immediate"),
            "expected immediate-store-object rejection, got: {err}"
        );
    }

    #[test]
    fn test_rootfs_store_path_binds_reject_store_subpath_before_mounting() {
        let temp = tempfile::TempDir::new().unwrap();
        let container_root = temp.path().join("container-root");
        let rootfs = temp.path().join("rootfs");
        std::fs::create_dir_all(&container_root).unwrap();
        std::fs::create_dir_all(&rootfs).unwrap();
        std::fs::write(
            rootfs.join(ROOTFS_STORE_PATHS_FILE),
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-hello/bin\n",
        )
        .unwrap();

        let err = bind_mount_rootfs_store_paths(&container_root, &rootfs).unwrap_err();

        assert!(
            err.to_string().contains("expected immediate"),
            "expected immediate-store-object rejection, got: {err}"
        );
    }

    #[test]
    fn test_proc_mask_includes_sysrq_trigger() {
        assert!(
            PROC_NULL_MASKED.contains(&"sysrq-trigger"),
            "/proc/sysrq-trigger must be masked to prevent host DoS"
        );
    }

    #[test]
    fn test_proc_mask_includes_timer_stats() {
        assert!(
            PROC_NULL_MASKED.contains(&"timer_stats"),
            "/proc/timer_stats must be masked to prevent kernel info leakage"
        );
    }

    #[test]
    fn test_proc_mask_includes_kpage_files() {
        for path in &["kpagecount", "kpageflags", "kpagecgroup"] {
            assert!(
                PROC_NULL_MASKED.contains(path),
                "/proc/{} must be masked to prevent host memory layout leakage",
                path
            );
        }
    }

    #[test]
    fn test_proc_mask_includes_oci_standard_paths() {
        // OCI runtime spec required masked paths
        for path in &["kallsyms", "kcore", "sched_debug", "keys", "config.gz"] {
            assert!(
                PROC_NULL_MASKED.contains(path),
                "/proc/{} must be in null-masked list (OCI spec)",
                path
            );
        }
        for path in &["acpi", "scsi"] {
            assert!(
                PROC_TMPFS_MASKED.contains(path),
                "/proc/{} must be in tmpfs-masked list (OCI spec)",
                path
            );
        }
        for path in &["bus", "fs", "irq", "sys"] {
            assert!(
                PROC_READONLY_PATHS.contains(path),
                "/proc/{} must be in read-only remount list (OCI spec)",
                path
            );
            assert!(
                !PROC_TMPFS_MASKED.contains(path),
                "/proc/{} must stay visible read-only, not hidden behind tmpfs",
                path
            );
        }
    }

    #[test]
    fn test_procfs_hidepid_failure_fails_closed_even_best_effort() {
        let err = handle_procfs_mount_failure(nix::errno::Errno::EINVAL, true, true).unwrap_err();

        assert!(
            err.to_string().contains("required hidepid=2"),
            "hidepid=2 failures must remain fatal in production/rootless paths, got: {err}"
        );
    }

    #[test]
    fn test_procfs_best_effort_only_applies_without_hidepid() {
        assert!(
            !handle_procfs_mount_failure(nix::errno::Errno::EPERM, true, false).unwrap(),
            "best-effort procfs mount failures may only continue when hidepid was not requested"
        );
    }

    #[test]
    fn test_parse_mountinfo_line_uses_mountinfo_mount_point_and_flags() {
        let line =
            "36 25 0:32 / /run/secrets rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=1024k";
        let (mount_point, flags) = parse_mountinfo_line(line).unwrap();

        assert_eq!(mount_point, "/run/secrets");
        assert!(flags.contains("nosuid"));
        assert!(flags.contains("nodev"));
        assert!(flags.contains("noexec"));
    }

    #[test]
    fn test_parse_mountinfo_line_decodes_escaped_mount_points() {
        let line = "41 25 0:40 / /path\\040with\\040spaces ro,nosuid,nodev - ext4 /dev/root ro";
        let (mount_point, flags) = parse_mountinfo_line(line).unwrap();

        assert_eq!(mount_point, "/path with spaces");
        assert!(flags.contains("ro"));
    }

    #[test]
    fn test_chroot_impl_closes_non_stdio_fds() {
        let source = include_str!("mount.rs");
        let fn_start = source.find("fn chroot_impl").unwrap();
        let after = &source[fn_start..];
        let open = after.find('{').unwrap();
        let mut depth = 0u32;
        let mut fn_end = open;
        for (i, ch) in after[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        fn_end = open + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        let body = &after[..fn_end];
        assert!(
            body.contains("close_non_stdio_fds_after_chroot()?"),
            "chroot fallback must close inherited non-stdio fds before continuing setup"
        );
    }

    #[test]
    fn test_read_regular_file_nofollow_reads_regular_file() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("secret.txt");
        std::fs::write(&path, "supersecret").unwrap();

        let content = read_regular_file_nofollow(&path).unwrap();
        assert_eq!(content, b"supersecret");
    }

    #[test]
    fn test_read_regular_file_nofollow_rejects_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target.txt");
        let link = temp.path().join("secret-link");
        std::fs::write(&target, "supersecret").unwrap();
        symlink(&target, &link).unwrap();

        let err = read_regular_file_nofollow(&link).unwrap_err();
        assert!(
            err.to_string().contains("O_NOFOLLOW"),
            "symlink reads must fail via O_NOFOLLOW"
        );
    }
}
