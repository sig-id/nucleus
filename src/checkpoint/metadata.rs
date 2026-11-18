use crate::container::{ContainerState, ContainerStateManager};
use crate::error::{NucleusError, Result};
use crate::resources::{IoDeviceLimit, ResourceLimits};
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::SystemTime;

/// Resource limits captured from the original cgroup at checkpoint time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointResourceLimits {
    pub memory_bytes: Option<u64>,
    pub memory_high: Option<u64>,
    pub memory_swap_max: Option<u64>,
    pub cpu_quota_us: Option<u64>,
    pub cpu_period_us: u64,
    pub cpu_weight: Option<u64>,
    pub pids_max: Option<u64>,
    pub io_limits: Vec<IoDeviceLimit>,
}

impl CheckpointResourceLimits {
    fn from_cgroup_dir(cgroup_path: &Path) -> Result<Self> {
        let (cpu_quota_us, cpu_period_us) = Self::read_cpu_quota(cgroup_path.join("cpu.max"))?;
        Ok(Self {
            memory_bytes: Self::read_optional_u64(cgroup_path.join("memory.max"))?,
            memory_high: Self::read_optional_u64(cgroup_path.join("memory.high"))?,
            memory_swap_max: Self::read_optional_u64(cgroup_path.join("memory.swap.max"))?,
            cpu_quota_us,
            cpu_period_us,
            cpu_weight: Self::read_optional_u64(cgroup_path.join("cpu.weight"))?,
            pids_max: Self::read_optional_u64(cgroup_path.join("pids.max"))?,
            io_limits: Self::read_io_limits(cgroup_path.join("io.max"))?,
        })
    }

    pub fn to_resource_limits(&self) -> ResourceLimits {
        ResourceLimits {
            memory_bytes: self.memory_bytes,
            memory_high: self.memory_high,
            memory_swap_max: self.memory_swap_max,
            cpu_quota_us: self.cpu_quota_us,
            cpu_period_us: self.cpu_period_us,
            cpu_weight: self.cpu_weight,
            pids_max: self.pids_max,
            io_limits: self.io_limits.clone(),
            memlock_bytes: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.to_resource_limits()
            .validate_runtime_sanity()
            .map_err(|e| {
                NucleusError::CheckpointError(format!("Invalid checkpoint resource limits: {}", e))
            })
    }

    pub fn cpu_limit_millicores(&self) -> Option<u64> {
        if self.cpu_period_us == 0 {
            return None;
        }
        self.cpu_quota_us
            .map(|quota| quota.saturating_mul(1000) / self.cpu_period_us)
    }

    fn read_optional_u64(path: impl AsRef<Path>) -> Result<Option<u64>> {
        let path = path.as_ref();
        let content = fs::read_to_string(path).map_err(|e| {
            NucleusError::CheckpointError(format!(
                "Failed to read cgroup limit file {:?}: {}",
                path, e
            ))
        })?;
        let value = content.trim();
        if value == "max" {
            return Ok(None);
        }
        value.parse::<u64>().map(Some).map_err(|e| {
            NucleusError::CheckpointError(format!(
                "Failed to parse cgroup limit file {:?}: {}",
                path, e
            ))
        })
    }

    fn read_cpu_quota(path: impl AsRef<Path>) -> Result<(Option<u64>, u64)> {
        let path = path.as_ref();
        let content = fs::read_to_string(path).map_err(|e| {
            NucleusError::CheckpointError(format!("Failed to read {:?}: {}", path, e))
        })?;
        let mut parts = content.split_whitespace();
        let quota = parts.next().ok_or_else(|| {
            NucleusError::CheckpointError(format!("Invalid cpu.max format in {:?}", path))
        })?;
        let period = parts.next().ok_or_else(|| {
            NucleusError::CheckpointError(format!("Missing cpu.max period in {:?}", path))
        })?;
        if parts.next().is_some() {
            return Err(NucleusError::CheckpointError(format!(
                "Invalid cpu.max format in {:?}",
                path
            )));
        }

        let cpu_quota_us = if quota == "max" {
            None
        } else {
            Some(quota.parse::<u64>().map_err(|e| {
                NucleusError::CheckpointError(format!("Failed to parse cpu.max quota: {}", e))
            })?)
        };
        let cpu_period_us = period.parse::<u64>().map_err(|e| {
            NucleusError::CheckpointError(format!("Failed to parse cpu.max period: {}", e))
        })?;
        if cpu_period_us == 0 {
            return Err(NucleusError::CheckpointError(format!(
                "Invalid cpu.max period in {:?}: period must be greater than 0",
                path
            )));
        }

        Ok((cpu_quota_us, cpu_period_us))
    }

    fn read_io_limits(path: impl AsRef<Path>) -> Result<Vec<IoDeviceLimit>> {
        let path = path.as_ref();
        let content = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(NucleusError::CheckpointError(format!(
                    "Failed to read {:?}: {}",
                    path, e
                )))
            }
        };

        content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(IoDeviceLimit::parse)
            .collect()
    }
}

/// Metadata stored alongside checkpoint images
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointMetadata {
    /// Container ID
    pub container_id: String,

    /// Container name
    pub container_name: String,

    /// Original PID
    pub original_pid: u32,

    /// Command that was running
    pub command: Vec<String>,

    /// Timestamp of checkpoint
    pub checkpoint_at: u64,

    /// Nucleus version
    pub version: String,

    /// Whether container was using gVisor
    pub using_gvisor: bool,

    /// Whether container was rootless
    pub rootless: bool,

    /// Original launch record, covered by the checkpoint HMAC. Older snapshots lack it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_state: Option<ContainerState>,

    /// Original cgroup path, if the container was tracked in a cgroup.
    #[serde(default)]
    pub cgroup_path: Option<String>,

    /// Resource limits captured from the original cgroup.
    #[serde(default)]
    pub resource_limits: Option<CheckpointResourceLimits>,
}

impl CheckpointMetadata {
    /// Create metadata from current container state
    pub fn from_state(state: &ContainerState) -> Result<Self> {
        let checkpoint_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let resource_limits = state
            .cgroup_path
            .as_deref()
            .map(|path| CheckpointResourceLimits::from_cgroup_dir(Path::new(path)))
            .transpose()?;

        Ok(Self {
            container_id: state.id.clone(),
            container_name: state.name.clone(),
            original_pid: state.pid,
            launch_state: Some(state.clone()),
            command: state.command.clone(),
            checkpoint_at,
            version: env!("CARGO_PKG_VERSION").to_string(),
            using_gvisor: state.using_gvisor,
            rootless: state.rootless,
            cgroup_path: state.cgroup_path.clone(),
            resource_limits,
        })
    }

    /// Save metadata to checkpoint directory
    pub fn save(&self, dir: &Path) -> Result<()> {
        let path = dir.join("metadata.json");
        let tmp_path = dir.join("metadata.json.tmp");
        let json = serde_json::to_string_pretty(self).map_err(|e| {
            NucleusError::CheckpointError(format!("Failed to serialize metadata: {}", e))
        })?;

        if tmp_path.exists() {
            let meta = fs::symlink_metadata(&tmp_path).map_err(|e| {
                NucleusError::CheckpointError(format!(
                    "Failed to inspect temp metadata file {:?}: {}",
                    tmp_path, e
                ))
            })?;
            if meta.file_type().is_symlink() {
                return Err(NucleusError::CheckpointError(format!(
                    "Refusing symlink temp metadata file {:?}",
                    tmp_path
                )));
            }
            fs::remove_file(&tmp_path).map_err(|e| {
                NucleusError::CheckpointError(format!(
                    "Failed to remove stale temp metadata file {:?}: {}",
                    tmp_path, e
                ))
            })?;
        }

        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp_path)
            .map_err(|e| {
                NucleusError::CheckpointError(format!(
                    "Failed to open temp metadata file {:?}: {}",
                    tmp_path, e
                ))
            })?;

        file.write_all(json.as_bytes()).map_err(|e| {
            NucleusError::CheckpointError(format!(
                "Failed to write metadata file {:?}: {}",
                tmp_path, e
            ))
        })?;
        file.sync_all().map_err(|e| {
            NucleusError::CheckpointError(format!(
                "Failed to sync metadata file {:?}: {}",
                tmp_path, e
            ))
        })?;

        fs::rename(&tmp_path, &path).map_err(|e| {
            NucleusError::CheckpointError(format!(
                "Failed to atomically replace metadata file {:?}: {}",
                path, e
            ))
        })?;
        Ok(())
    }

    /// Load metadata from checkpoint directory
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join("metadata.json");
        let json = ContainerStateManager::read_file_nofollow(&path).map_err(|e| {
            NucleusError::CheckpointError(format!("Failed to read metadata {:?}: {}", path, e))
        })?;
        let metadata: Self = serde_json::from_str(&json).map_err(|e| {
            NucleusError::CheckpointError(format!("Failed to parse metadata: {}", e))
        })?;
        if let Some(resource_limits) = metadata.resource_limits.as_ref() {
            resource_limits.validate()?;
        }
        Ok(metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs as unix_fs;

    #[test]
    fn test_save_rejects_symlink_target() {
        // BUG-11: CheckpointMetadata::save must use O_NOFOLLOW to prevent
        // symlink attacks. Verify by creating a symlink at the temp file path
        // and confirming save() refuses to follow it.
        let dir = tempfile::tempdir().unwrap();
        let attacker_target = dir.path().join("attacker-owned-file");
        std::fs::write(&attacker_target, "").unwrap();

        // Pre-create the symlink where save() will write its temp file
        let symlink_path = dir.path().join("metadata.json.tmp");
        unix_fs::symlink(&attacker_target, &symlink_path).unwrap();

        let metadata = CheckpointMetadata {
            container_id: "test-id".to_string(),
            container_name: "test".to_string(),
            original_pid: 1,
            launch_state: None,
            command: vec!["/bin/sh".to_string()],
            checkpoint_at: 0,
            version: "0.0.0".to_string(),
            using_gvisor: false,
            rootless: false,
            cgroup_path: None,
            resource_limits: None,
        };

        let result = metadata.save(dir.path());
        assert!(
            result.is_err(),
            "save() must reject symlink at temp file path (O_NOFOLLOW / symlink check)"
        );
    }

    #[test]
    fn test_checkpoint_resource_limits_from_cgroup_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("memory.max"), "536870912\n").unwrap();
        std::fs::write(dir.path().join("memory.high"), "483183820\n").unwrap();
        std::fs::write(dir.path().join("memory.swap.max"), "0\n").unwrap();
        std::fs::write(dir.path().join("cpu.max"), "50000 100000\n").unwrap();
        std::fs::write(dir.path().join("cpu.weight"), "100\n").unwrap();
        std::fs::write(dir.path().join("pids.max"), "256\n").unwrap();
        std::fs::write(dir.path().join("io.max"), "8:0 rbps=1048576 wbps=2097152\n").unwrap();

        let limits = CheckpointResourceLimits::from_cgroup_dir(dir.path()).unwrap();
        assert_eq!(limits.memory_bytes, Some(536_870_912));
        assert_eq!(limits.memory_high, Some(483_183_820));
        assert_eq!(limits.memory_swap_max, Some(0));
        assert_eq!(limits.cpu_quota_us, Some(50_000));
        assert_eq!(limits.cpu_period_us, 100_000);
        assert_eq!(limits.cpu_weight, Some(100));
        assert_eq!(limits.pids_max, Some(256));
        assert_eq!(limits.io_limits.len(), 1);
        assert_eq!(limits.cpu_limit_millicores(), Some(500));
    }

    #[test]
    fn test_load_rejects_zero_cpu_period_in_metadata() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("metadata.json"),
            r#"{
  "container_id": "test-id",
  "container_name": "test",
  "original_pid": 1,
  "command": ["/bin/sh"],
  "checkpoint_at": 0,
  "version": "0.0.0",
  "using_gvisor": false,
  "rootless": false,
  "cgroup_path": "/sys/fs/cgroup/nucleus-test",
  "resource_limits": {
    "memory_bytes": null,
    "memory_high": null,
    "memory_swap_max": null,
    "cpu_quota_us": 50000,
    "cpu_period_us": 0,
    "cpu_weight": null,
    "pids_max": 256,
    "io_limits": []
  }
}"#,
        )
        .unwrap();

        let err = CheckpointMetadata::load(dir.path()).unwrap_err();
        assert!(err
            .to_string()
            .contains("Invalid checkpoint resource limits"));
    }
}
