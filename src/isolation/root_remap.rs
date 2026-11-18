//! Host-wide reservations survive crashes, reboots and deletion of a container's
//! state. Bind mounts, checkpoints and persistent overlays can retain its IDs.
use super::{IdMapping, UserNamespaceConfig};
use crate::error::{NucleusError, Result};
use std::collections::hash_map::RandomState;
use std::fs::{self, File};
use std::hash::BuildHasher;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const BLOCK_SIZE: u32 = 65_536;
// Stay below signed-ID limits and outside systemd's default nspawn and shared
// foreign-image ranges. See https://systemd.io/UIDS-GIDS/.
const FIRST_SLOT: usize = 0x7000;
const END_SLOT: usize = 0x7ffe;
const ID_SLOTS: usize = 1 << 16;
const REGISTRY: &str = "/var/lib/nucleus/userns-ranges";

fn read_policy(path: &str) -> Result<String> {
    fs::read_to_string(path).map_err(|e| {
        NucleusError::ConfigError(format!("Cannot check root remap policy {path}: {e}"))
    })
}

fn check_subid_backend(config: &str) -> Result<()> {
    for line in config.lines() {
        let Some((key, value)) = line.split('#').next().unwrap_or("").split_once(':') else {
            continue;
        };
        if matches!(key.trim(), "subid" | "subuid" | "subgid") && value.trim() != "files" {
            return Err(NucleusError::ConfigError(
                "Automatic root remapping requires file-based subordinate ID delegation".into(),
            ));
        }
    }
    Ok(())
}

fn exclude_ids(blocked: &mut [bool], path: &str, contents: &str) -> Result<()> {
    for (i, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let invalid =
            || NucleusError::ConfigError(format!("Invalid ID entry in {path} at line {}", i + 1));
        let mut fields = line.split(':');
        fields
            .next()
            .filter(|name| !name.is_empty())
            .ok_or_else(invalid)?;
        let mut number = || {
            fields
                .next()
                .and_then(|v| v.parse::<u32>().ok())
                .ok_or_else(invalid)
        };
        if matches!(path, "/etc/subuid" | "/etc/subgid") {
            let start = number()?;
            let count = number()?;
            let last = count
                .checked_sub(1)
                .and_then(|n| start.checked_add(n))
                .ok_or_else(invalid)?;
            if fields.next().is_some() {
                return Err(invalid());
            }
            blocked[(start / BLOCK_SIZE) as usize..=(last / BLOCK_SIZE) as usize].fill(true);
        } else {
            // passwd also assigns a primary GID, even if group has no entry for it.
            fields.next().ok_or_else(invalid)?;
            for _ in 0..if path == "/etc/passwd" { 2 } else { 1 } {
                let id = fields
                    .next()
                    .and_then(|v| v.parse::<u32>().ok())
                    .ok_or_else(invalid)?;
                blocked[(id / BLOCK_SIZE) as usize] = true;
            }
        }
    }
    Ok(())
}

fn reserve(
    dir: &Path,
    blocked: &[bool],
    seed: usize,
    container_id: &str,
) -> Result<UserNamespaceConfig> {
    let slots = END_SLOT - FIRST_SLOT;
    for offset in 0..slots {
        let slot = FIRST_SLOT + (seed % slots + offset) % slots;
        if blocked[slot] {
            continue;
        }
        let start = slot as u32 * BLOCK_SIZE;
        // O_EXCL arbitrates concurrent launches, including identical IDs under
        // different --root paths. Even an empty claim after a crash stays taken.
        match File::create_new(dir.join(start.to_string())) {
            Ok(mut claim) => {
                writeln!(claim, "{container_id}")?;
                claim.sync_all()?;
                File::open(dir)?.sync_all()?;
                tracing::info!(container_id, start, "Reserved root-remapped UID/GID range");
                let map = IdMapping::new(0, start, BLOCK_SIZE);
                return Ok(UserNamespaceConfig {
                    uid_mappings: vec![map.clone()],
                    gid_mappings: vec![map],
                });
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(NucleusError::ConfigError(
        "No free 65536-ID root remap range remains".into(),
    ))
}

pub(super) fn allocate(container_id: &str) -> Result<UserNamespaceConfig> {
    if !nix::unistd::Uid::effective().is_root() {
        return Err(NucleusError::ConfigError(
            "Automatic root remapping requires host root".into(),
        ));
    }
    check_subid_backend(&read_policy("/etc/nsswitch.conf")?)?;
    let mut blocked = vec![false; ID_SLOTS];
    for path in ["/etc/subuid", "/etc/subgid", "/etc/passwd", "/etc/group"] {
        exclude_ids(&mut blocked, path, &read_policy(path)?)?;
    }
    let dir = crate::filesystem::trusted_directory(Path::new(REGISTRY), true)?;
    let meta = fs::metadata(&dir)?;
    if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        return Err(NucleusError::ConfigError(format!(
            "Insecure root remap registry {dir:?}"
        )));
    }
    // Persist both potentially newly created directory entries before using a claim.
    File::open("/var/lib")?.sync_all()?;
    File::open("/var/lib/nucleus")?.sync_all()?;
    reserve(
        &dir,
        &blocked,
        RandomState::new().hash_one(container_id) as usize,
        container_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn skips_every_intersecting_delegation_and_local_account() {
        let mut blocked = vec![false; ID_SLOTS];
        let start = FIRST_SLOT as u32 * BLOCK_SIZE;
        let id = |slot: u32| start + slot * BLOCK_SIZE;
        exclude_ids(
            &mut blocked,
            "/etc/subuid",
            &format!("# local\ndev:100000:65536\n1000:{}:2\n", id(1) - 1),
        )
        .unwrap();
        exclude_ids(
            &mut blocked,
            "/etc/subgid",
            &format!("someone:{}:1\n", id(2) + 1),
        )
        .unwrap();
        exclude_ids(
            &mut blocked,
            "/etc/passwd",
            &format!("service:x:{}:{}::/:/bin/false\n", id(3), id(4)),
        )
        .unwrap();
        exclude_ids(
            &mut blocked,
            "/etc/group",
            &format!("service:x:{}:\n", id(5)),
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let map = reserve(dir.path(), &blocked, 0, "first").unwrap();
        assert!(blocked[1] && blocked[2]);
        assert_eq!(map.uid_mappings, vec![IdMapping::new(0, id(6), BLOCK_SIZE)]);
        assert_eq!(map.uid_mappings, map.gid_mappings);
    }

    #[test]
    fn simultaneous_claims_survive_reopen_even_for_the_same_container_id() {
        let dir = tempfile::tempdir().unwrap();
        let blocked = vec![false; ID_SLOTS];
        let starts = std::thread::scope(|s| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    s.spawn(|| {
                        reserve(dir.path(), &blocked, 0, "same-id")
                            .unwrap()
                            .uid_mappings[0]
                            .host_id
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<HashSet<_>>()
        });
        assert_eq!(starts.len(), 8);
        let next = reserve(dir.path(), &blocked, 0, "later").unwrap();
        assert!(!starts.contains(&next.uid_mappings[0].host_id));
    }

    #[test]
    fn invalid_policy_or_exhaustion_fails_closed() {
        let mut blocked = vec![false; ID_SLOTS];
        for line in ["dev:x:65536", "dev:0:0", "dev:4294967295:2", "dev:1:2:3"] {
            assert!(exclude_ids(&mut blocked, "/etc/subuid", line).is_err());
        }
        assert!(check_subid_backend("subid: sss").is_err());
        check_subid_backend("passwd: files systemd\nsubid: files # delegated locally").unwrap();
        exclude_ids(&mut blocked, "/etc/subuid", "dev:0:4294967295").unwrap();
        let dir = tempfile::tempdir().unwrap();
        assert!(reserve(dir.path(), &blocked, 0, "full").is_err());
        assert!(dir.path().read_dir().unwrap().next().is_none());
    }
}
