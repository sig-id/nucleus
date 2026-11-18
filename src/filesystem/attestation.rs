use crate::error::{NucleusError, Result};
use crate::filesystem::ContextPopulator;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::io::{BufReader, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

pub const ROOTFS_ATTESTATION_FILE: &str = ".nucleus-rootfs-sha256";
pub const ROOTFS_STORE_PATHS_FILE: &str = ".nucleus-rootfs-store-paths";
const NIX_STORE_HASH_LEN: usize = 32;
const NIX_STORE_HASH_ALPHABET: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";

pub type DirectoryManifest = BTreeMap<String, String>;

#[derive(Clone, Copy)]
enum ScanMode<'a> {
    Context,
    Rootfs(&'a RootfsSources),
}

pub fn snapshot_context_dir(root: &Path) -> Result<DirectoryManifest> {
    let mut manifest = BTreeMap::new();
    scan_dir(root, root, ScanMode::Context, &mut manifest)?;
    Ok(manifest)
}

pub fn verify_context_integrity(source: &Path, dest: &Path) -> Result<()> {
    let expected = snapshot_context_dir(source)?;
    verify_context_manifest(&expected, dest)
}

pub fn verify_context_manifest(expected: &DirectoryManifest, dest: &Path) -> Result<()> {
    let actual = snapshot_context_dir(dest)?;
    compare_manifests(expected, &actual, "context")
}

pub fn verify_rootfs_attestation(root: &Path) -> Result<PathBuf> {
    let resolved = root.canonicalize()?;
    if root != resolved && is_immediate_nix_store_object_path(root) {
        return Err(NucleusError::FilesystemError(format!(
            "Configured store rootfs changed identity: {root:?}"
        )));
    }
    let root = resolved;
    if !is_immediate_nix_store_object_path(&root) {
        return Err(NucleusError::FilesystemError(format!(
            "Attested rootfs must be a registered Nix store object: {root:?}"
        )));
    }
    // Verify against the host store database before consuming the in-tree
    // manifest or its dependency list. Never take the verifier from PATH.
    verify_registered_objects(std::slice::from_ref(&root))?;
    let sources = RootfsSources::load(&root)?;
    let closure: Vec<_> = sources.store_paths.iter().cloned().collect();
    for group in closure.chunks(128) {
        verify_registered_objects(group)?;
    }
    for object in std::iter::once(&root).chain(&closure) {
        verify_store_metadata(object)?;
    }
    let expected = read_rootfs_attestation(&root)?;
    let mut actual = BTreeMap::new();
    scan_dir(&root, &root, ScanMode::Rootfs(&sources), &mut actual)?;
    compare_manifests(&expected, &actual, "rootfs")?;
    Ok(root)
}

fn verify_registered_objects(objects: &[PathBuf]) -> Result<()> {
    let tool = [
        option_env!("NUCLEUS_PACKAGED_NIX_STORE"),
        Some("/run/current-system/sw/bin/nix-store"),
        Some("/nix/var/nix/profiles/default/bin/nix-store"),
        Some("/usr/bin/nix-store"),
    ]
    .into_iter()
    .flatten()
    .find(|p| Path::new(p).is_file())
    .ok_or_else(|| {
        NucleusError::FilesystemError("Rootfs verification requires host nix-store".into())
    })?;
    let status = std::process::Command::new(tool)
        .env_clear()
        .env("HOME", "/")
        .args(["--store", "daemon", "--verify-path"])
        .args(objects)
        .status()?;
    if !status.success() {
        return Err(NucleusError::FilesystemError(format!(
            "Host Nix store integrity verification failed: {status}"
        )));
    }
    Ok(())
}

// The registered NAR hash covers node type, directory membership, symlink
// text, contents and executability. Verify the metadata NAR omits separately.
fn verify_store_metadata(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    let mode = m.mode() & 0o7777;
    let valid = if m.is_symlink() {
        mode == 0o777
    } else if m.is_dir() {
        mode == 0o555
    } else {
        m.is_file() && matches!(mode, 0o444 | 0o555)
    };
    if !valid || m.uid() != 0 || m.gid() != 0 {
        return Err(NucleusError::FilesystemError(format!(
            "Invalid Nix store ownership, mode or file type at {path:?}"
        )));
    }
    if m.is_dir() {
        for entry in fs::read_dir(path)? {
            verify_store_metadata(&entry?.path())?;
        }
    }
    Ok(())
}

pub(crate) struct RootfsSources {
    root: PathBuf,
    dir: std::os::fd::OwnedFd,
    pub store_paths: BTreeSet<PathBuf>,
}

impl RootfsSources {
    pub fn load(root: &Path) -> Result<Self> {
        let root = root.canonicalize()?;
        let dir = nix::fcntl::open(
            &root,
            nix::fcntl::OFlag::O_PATH
                | nix::fcntl::OFlag::O_DIRECTORY
                | nix::fcntl::OFlag::O_NOFOLLOW
                | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )?;
        if fs::read_link(super::fd_path(&dir))? != root {
            return Err(NucleusError::FilesystemError(format!(
                "Rootfs changed during setup: {root:?}"
            )));
        }
        let path = super::fd_path(&dir).join(ROOTFS_STORE_PATHS_FILE);
        let mut store_paths = BTreeSet::new();
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
            Ok(_) => {
                let data = super::read_regular_file_nofollow(&path)?;
                let data = std::str::from_utf8(&data).map_err(|_| {
                    NucleusError::FilesystemError(format!("Invalid UTF-8 in {path:?}"))
                })?;
                for line in data.lines().map(str::trim).filter(|s| !s.is_empty()) {
                    let object = Path::new(line);
                    if !is_immediate_nix_store_object_path(object)
                        || object.canonicalize()? != object
                    {
                        return Err(NucleusError::FilesystemError(format!("Invalid rootfs store path {line:?}: expected immediate /nix/store object")));
                    }
                    store_paths.insert(object.to_owned());
                }
            }
        }
        Ok(Self {
            root,
            dir,
            store_paths,
        })
    }

    pub fn validate_resolved(&self, resolved: &Path) -> Result<()> {
        if resolved.starts_with(&self.root)
            || resolved.ancestors().any(|p| self.store_paths.contains(p))
        {
            return Ok(());
        }
        Err(NucleusError::FilesystemError(format!(
            "Rootfs source resolves outside allowed roots: {resolved:?}"
        )))
    }

    pub fn open_subdir(&self, name: &str) -> Result<Option<std::os::fd::OwnedFd>> {
        use nix::fcntl::{openat, OFlag};
        let fd = match openat(
            &self.dir,
            name,
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(nix::errno::Errno::ENOENT) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        self.validate_resolved(&fs::read_link(super::fd_path(&fd))?)?;
        Ok(Some(fd))
    }
}

pub fn read_rootfs_attestation(root: &Path) -> Result<DirectoryManifest> {
    read_manifest_file(&root.join(ROOTFS_ATTESTATION_FILE))
}

pub fn is_immediate_nix_store_object_path(path: &Path) -> bool {
    immediate_nix_store_object_name(path).is_some()
}

fn immediate_nix_store_object_name(path: &Path) -> Option<&OsStr> {
    let (store_name, has_trailing_components) = nix_store_object_name(path)?;
    if has_trailing_components || !is_valid_nix_store_object_name(store_name) {
        return None;
    }
    Some(store_name)
}

fn nix_store_object_name(path: &Path) -> Option<(&OsStr, bool)> {
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return None;
    }
    match components.next() {
        Some(Component::Normal(component)) if component == OsStr::new("nix") => {}
        _ => return None,
    }
    match components.next() {
        Some(Component::Normal(component)) if component == OsStr::new("store") => {}
        _ => return None,
    }
    let store_name = match components.next() {
        Some(Component::Normal(component)) => component,
        _ => return None,
    };
    Some((store_name, components.next().is_some()))
}

fn is_valid_nix_store_object_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some((hash, package_name)) = name.split_once('-') else {
        return false;
    };

    hash.len() == NIX_STORE_HASH_LEN
        && !package_name.is_empty()
        && package_name != "."
        && package_name != ".."
        && hash
            .bytes()
            .all(|byte| NIX_STORE_HASH_ALPHABET.contains(&byte))
        && package_name.bytes().all(is_valid_nix_store_name_byte)
}

fn is_valid_nix_store_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.' | b'_' | b'?' | b'=')
}

fn read_manifest_file(path: &Path) -> Result<DirectoryManifest> {
    let content = String::from_utf8(super::read_regular_file_nofollow(path)?).map_err(|e| {
        NucleusError::FilesystemError(format!("Failed to read manifest {:?}: {}", path, e))
    })?;

    let mut manifest = BTreeMap::new();
    for (line_no, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let Some((digest, rel_path)) = line.split_once('\t') else {
            return Err(NucleusError::FilesystemError(format!(
                "Invalid attestation line {} in {:?}: expected '<sha256>\\t<path>'",
                line_no + 1,
                path
            )));
        };
        manifest.insert(rel_path.to_string(), digest.to_string());
    }

    Ok(manifest)
}

fn compare_manifests(
    expected: &DirectoryManifest,
    actual: &DirectoryManifest,
    label: &str,
) -> Result<()> {
    if expected == actual {
        return Ok(());
    }

    let mut missing = Vec::new();
    let mut mismatched = Vec::new();
    let mut extra = Vec::new();

    for (path, digest) in expected {
        match actual.get(path) {
            Some(actual_digest) if actual_digest == digest => {}
            Some(actual_digest) => mismatched.push(format!(
                "{} (expected {}, got {})",
                path, digest, actual_digest
            )),
            None => missing.push(path.clone()),
        }
    }

    for path in actual.keys() {
        if !expected.contains_key(path) {
            extra.push(path.clone());
        }
    }

    let mut details = Vec::new();
    if !missing.is_empty() {
        details.push(format!("missing: {}", summarize(&missing)));
    }
    if !mismatched.is_empty() {
        details.push(format!("mismatched: {}", summarize(&mismatched)));
    }
    if !extra.is_empty() {
        details.push(format!("extra: {}", summarize(&extra)));
    }

    Err(NucleusError::FilesystemError(format!(
        "{} integrity verification failed ({})",
        label,
        details.join("; ")
    )))
}

fn summarize(items: &[String]) -> String {
    const LIMIT: usize = 5;
    if items.len() <= LIMIT {
        items.join(", ")
    } else {
        format!("{}, ... ({} total)", items[..LIMIT].join(", "), items.len())
    }
}

fn scan_dir(
    root: &Path,
    current: &Path,
    mode: ScanMode,
    manifest: &mut DirectoryManifest,
) -> Result<()> {
    let mut entries: Vec<_> = fs::read_dir(current)
        .map_err(|e| {
            NucleusError::FilesystemError(format!("Failed to read directory {:?}: {}", current, e))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| {
            NucleusError::FilesystemError(format!("Failed to enumerate {:?}: {}", current, e))
        })?;
    entries.sort_by_key(|a| a.file_name());

    for entry in entries {
        let path = entry.path();
        let name = entry.file_name();

        if should_skip(&mode, &name, &path, root)? {
            continue;
        }

        match mode {
            ScanMode::Context => scan_context_entry(root, &path, manifest)?,
            ScanMode::Rootfs(sources) => scan_rootfs_entry(root, &path, manifest, sources)?,
        }
    }

    Ok(())
}

fn should_skip(mode: &ScanMode, name: &OsStr, path: &Path, root: &Path) -> Result<bool> {
    match mode {
        ScanMode::Context => Ok(ContextPopulator::should_exclude_name(name)),
        ScanMode::Rootfs(_) => {
            let rel = relative_path(root, path)?;
            Ok(rel == ROOTFS_ATTESTATION_FILE)
        }
    }
}

fn scan_context_entry(root: &Path, path: &Path, manifest: &mut DirectoryManifest) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| NucleusError::FilesystemError(format!("Failed to stat {:?}: {}", path, e)))?;

    if metadata.is_symlink() {
        return Ok(());
    }

    if metadata.is_dir() {
        scan_dir(root, path, ScanMode::Context, manifest)?;
        return Ok(());
    }

    if metadata.is_file() {
        manifest.insert(relative_path(root, path)?, hash_file(path)?);
    }

    Ok(())
}

fn scan_rootfs_entry(
    root: &Path,
    path: &Path,
    manifest: &mut DirectoryManifest,
    sources: &RootfsSources,
) -> Result<()> {
    let symlink_metadata = fs::symlink_metadata(path)
        .map_err(|e| NucleusError::FilesystemError(format!("Failed to stat {:?}: {}", path, e)))?;
    if symlink_metadata.is_symlink() {
        sources.validate_resolved(&path.canonicalize()?)?;
    }

    let metadata = fs::metadata(path)
        .map_err(|e| NucleusError::FilesystemError(format!("Failed to stat {:?}: {}", path, e)))?;

    if metadata.is_dir() {
        scan_dir(root, path, ScanMode::Rootfs(sources), manifest)?;
        return Ok(());
    }

    if metadata.is_file() {
        manifest.insert(relative_path(root, path)?, hash_file(path)?);
    }

    Ok(())
}

fn relative_path(root: &Path, path: &Path) -> Result<String> {
    let rel = path.strip_prefix(root).map_err(|e| {
        NucleusError::FilesystemError(format!(
            "Failed to compute relative path for {:?} under {:?}: {}",
            path, root, e
        ))
    })?;

    path_to_string(rel)
}

fn path_to_string(path: &Path) -> Result<String> {
    path.to_str()
        .map(|p| p.trim_start_matches('/').to_string())
        .ok_or_else(|| {
            NucleusError::FilesystemError(format!("Non-UTF-8 path in attestation: {:?}", path))
        })
}

fn hash_file(path: &Path) -> Result<String> {
    let file = fs::File::open(path)
        .map_err(|e| NucleusError::FilesystemError(format!("Failed to open {:?}: {}", path, e)))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];

    loop {
        let read = reader.read(&mut buf).map_err(|e| {
            NucleusError::FilesystemError(format!("Failed to read {:?}: {}", path, e))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }

    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_manifest_skips_symlinks_and_excluded_files() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        fs::write(root.join("README.md"), "ok").unwrap();
        fs::write(root.join(".env"), "secret").unwrap();
        std::os::unix::fs::symlink(root.join("README.md"), root.join("link")).unwrap();

        let manifest = snapshot_context_dir(root).unwrap();
        assert!(manifest.contains_key("README.md"));
        assert!(!manifest.contains_key(".env"));
        assert!(!manifest.contains_key("link"));
    }

    #[test]
    fn test_compare_manifest_reports_mismatch() {
        let expected = BTreeMap::from([(String::from("a"), String::from("deadbeef"))]);
        let actual = BTreeMap::from([(String::from("a"), String::from("cafebabe"))]);

        let err = compare_manifests(&expected, &actual, "context").unwrap_err();
        assert!(err.to_string().contains("integrity verification failed"));
    }

    #[test]
    fn test_read_manifest_file() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("manifest");
        fs::write(&path, "abc\tbin/tool\n").unwrap();

        let manifest = read_manifest_file(&path).unwrap();
        assert_eq!(manifest.get("bin/tool").unwrap(), "abc");
    }

    #[test]
    fn test_immediate_nix_store_object_path_validation() {
        let valid = Path::new("/nix/store/0123456789abcdfghijklmnpqrsvwxyz-hello-2.12.1");
        assert!(is_immediate_nix_store_object_path(valid));

        for path in [
            "/nix/store",
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-hello/bin",
            "/nix/store/0123456789abcdfghijklmnpqrsvwxy-hello",
            "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-hello",
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-",
            "/tmp/nix/store/0123456789abcdfghijklmnpqrsvwxyz-hello",
        ] {
            assert!(
                !is_immediate_nix_store_object_path(Path::new(path)),
                "{path} must not be accepted as an immediate Nix store object"
            );
        }
    }

    #[test]
    fn rootfs_subdirs_are_confined_without_attestation() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("etc")).unwrap();
        let sources = RootfsSources::load(dir.path()).unwrap();
        assert!(sources.open_subdir("etc").is_err());
        let undeclared = Path::new("/nix/store/0123456789abcdfghijklmnpqrsvwxyz-other/lib");
        assert!(sources.validate_resolved(undeclared).is_err());
    }

    #[test]
    #[ignore = "requires root to test ownership and canonical store metadata"]
    fn rejects_noncanonical_store_metadata() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        fs::write(&file, b"fixture").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o555)).unwrap();
        verify_store_metadata(&file).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o4555)).unwrap();
        assert!(verify_store_metadata(&file).is_err());
        fs::set_permissions(&file, fs::Permissions::from_mode(0o444)).unwrap();
        nix::unistd::chown(&file, Some(nix::unistd::Uid::from_raw(1234)), None).unwrap();
        assert!(verify_store_metadata(&file).is_err());
        let fifo = dir.path().join("pipe");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRUSR).unwrap();
        assert!(verify_store_metadata(&fifo).is_err());
    }

    #[test]
    #[ignore = "requires a trusted host Nix daemon and canonical store ownership"]
    fn verify_registered_rootfs_with_empty_directory() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("attestation-fixture");
        fs::create_dir_all(root.join("empty")).unwrap();
        fs::write(root.join(ROOTFS_ATTESTATION_FILE), "").unwrap();
        let output = std::process::Command::new("nix-store")
            .args(["--store", "daemon", "--add"])
            .arg(&root)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        verify_rootfs_attestation(Path::new(
            std::str::from_utf8(&output.stdout).unwrap().trim(),
        ))
        .unwrap();
        if let Some(root) = std::env::var_os("NUCLEUS_TEST_ATTESTED_ROOTFS") {
            verify_rootfs_attestation(Path::new(&root)).unwrap();
        }
    }

    #[test]
    fn test_rootfs_attestation_rejects_symlink_targets_outside_allowed_roots() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("rootfs");
        fs::create_dir_all(root.join("bin")).unwrap();

        let outside = temp.path().join("host-secret");
        fs::write(&outside, "host-only").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("bin/tool")).unwrap();

        let digest = hash_file(&outside).unwrap();
        fs::write(
            root.join(ROOTFS_ATTESTATION_FILE),
            format!("{}\tbin/tool\n", digest),
        )
        .unwrap();

        assert!(verify_rootfs_attestation(&root)
            .unwrap_err()
            .to_string()
            .contains("registered Nix store object"));
        let sources = RootfsSources::load(&root).unwrap();
        let err = sources.validate_resolved(&outside).unwrap_err();
        assert!(err.to_string().contains("outside allowed roots"));
    }
}
