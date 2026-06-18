use crate::error::{NucleusError, Result};
use crate::filesystem::ContextPopulator;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::io::{BufReader, Read};
use std::path::{Component, Path};

pub const ROOTFS_ATTESTATION_FILE: &str = ".nucleus-rootfs-sha256";
pub const ROOTFS_STORE_PATHS_FILE: &str = ".nucleus-rootfs-store-paths";
const NIX_STORE_HASH_LEN: usize = 32;
const NIX_STORE_HASH_ALPHABET: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";

pub type DirectoryManifest = BTreeMap<String, String>;

#[derive(Clone, Copy)]
enum ScanMode {
    Context,
    Rootfs,
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

pub fn verify_rootfs_attestation(root: &Path) -> Result<()> {
    let manifest_path = root.join(ROOTFS_ATTESTATION_FILE);
    if !manifest_path.exists() {
        return Err(NucleusError::FilesystemError(format!(
            "Rootfs attestation requested but manifest is missing: {:?}",
            manifest_path
        )));
    }

    let expected = read_manifest_file(&manifest_path)?;
    let mut actual = BTreeMap::new();
    scan_dir(root, root, ScanMode::Rootfs, &mut actual)?;
    compare_manifests(&expected, &actual, "rootfs")
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
    let content = fs::read_to_string(path).map_err(|e| {
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
            ScanMode::Rootfs => scan_rootfs_entry(root, &path, manifest)?,
        }
    }

    Ok(())
}

fn should_skip(mode: &ScanMode, name: &OsStr, path: &Path, root: &Path) -> Result<bool> {
    match mode {
        ScanMode::Context => Ok(ContextPopulator::should_exclude_name(name)),
        ScanMode::Rootfs => {
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

fn scan_rootfs_entry(root: &Path, path: &Path, manifest: &mut DirectoryManifest) -> Result<()> {
    let symlink_metadata = fs::symlink_metadata(path)
        .map_err(|e| NucleusError::FilesystemError(format!("Failed to stat {:?}: {}", path, e)))?;
    if symlink_metadata.is_symlink() {
        validate_rootfs_symlink_target(root, path)?;
    }

    let metadata = fs::metadata(path)
        .map_err(|e| NucleusError::FilesystemError(format!("Failed to stat {:?}: {}", path, e)))?;

    if metadata.is_dir() {
        scan_dir(root, path, ScanMode::Rootfs, manifest)?;
        return Ok(());
    }

    if metadata.is_file() {
        manifest.insert(relative_path(root, path)?, hash_file(path)?);
    }

    Ok(())
}

fn validate_rootfs_symlink_target(root: &Path, path: &Path) -> Result<()> {
    let resolved = fs::canonicalize(path).map_err(|e| {
        NucleusError::FilesystemError(format!(
            "Failed to resolve rootfs symlink target {:?}: {}",
            path, e
        ))
    })?;
    let canonical_root = fs::canonicalize(root).map_err(|e| {
        NucleusError::FilesystemError(format!("Failed to resolve rootfs {:?}: {}", root, e))
    })?;

    if resolved.starts_with(&canonical_root) {
        return Ok(());
    }
    if let Some((store_name, _)) = nix_store_object_name(&resolved) {
        if is_valid_nix_store_object_name(store_name) {
            return Ok(());
        }
        return Err(NucleusError::FilesystemError(format!(
            "Rootfs symlink {:?} resolves to invalid /nix/store path: {:?}",
            path, resolved
        )));
    }

    Err(NucleusError::FilesystemError(format!(
        "Rootfs symlink {:?} resolves outside allowed roots: {:?}",
        path, resolved
    )))
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

        let err = verify_rootfs_attestation(&root).unwrap_err();
        assert!(err.to_string().contains("outside allowed roots"));
    }
}
