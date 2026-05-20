use crate::error::{NucleusError, Result};
use serde::{Deserialize, Serialize};

/// Per-device I/O throttling limit
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IoDeviceLimit {
    /// Device identifier in "major:minor" format
    pub device: String,
    /// Read IOPS limit
    pub riops: Option<u64>,
    /// Write IOPS limit
    pub wiops: Option<u64>,
    /// Read bytes/sec limit
    pub rbps: Option<u64>,
    /// Write bytes/sec limit
    pub wbps: Option<u64>,
}

impl IoDeviceLimit {
    /// Parse an I/O device limit spec like "8:0 riops=1000 wbps=10485760"
    pub fn parse(s: &str) -> Result<Self> {
        let mut parts = s.split_whitespace();

        let device = parts
            .next()
            .ok_or_else(|| NucleusError::InvalidResourceLimit("Empty I/O limit spec".into()))?;

        // Validate device format: "major:minor"
        let mut dev_parts = device.split(':');
        let major = dev_parts.next().and_then(|s| s.parse::<u64>().ok());
        let minor = dev_parts.next().and_then(|s| s.parse::<u64>().ok());
        if major.is_none() || minor.is_none() || dev_parts.next().is_some() {
            return Err(NucleusError::InvalidResourceLimit(format!(
                "Invalid device format '{}', expected 'major:minor'",
                device
            )));
        }

        let mut limit = Self {
            device: device.to_string(),
            riops: None,
            wiops: None,
            rbps: None,
            wbps: None,
        };

        for param in parts {
            let (key, value) = param.split_once('=').ok_or_else(|| {
                NucleusError::InvalidResourceLimit(format!(
                    "Invalid I/O param '{}', expected key=value",
                    param
                ))
            })?;
            let value: u64 = value.parse().map_err(|_| {
                NucleusError::InvalidResourceLimit(format!("Invalid I/O value: {}", value))
            })?;

            match key {
                "riops" => limit.riops = Some(value),
                "wiops" => limit.wiops = Some(value),
                "rbps" => limit.rbps = Some(value),
                "wbps" => limit.wbps = Some(value),
                _ => {
                    return Err(NucleusError::InvalidResourceLimit(format!(
                        "Unknown I/O param '{}'",
                        key
                    )));
                }
            }
        }

        Ok(limit)
    }

    /// Format as cgroup v2 io.max line: "major:minor riops=X wiops=Y rbps=Z wbps=W"
    pub fn to_io_max_line(&self) -> String {
        let mut parts = vec![self.device.clone()];
        if let Some(v) = self.riops {
            parts.push(format!("riops={}", v));
        }
        if let Some(v) = self.wiops {
            parts.push(format!("wiops={}", v));
        }
        if let Some(v) = self.rbps {
            parts.push(format!("rbps={}", v));
        }
        if let Some(v) = self.wbps {
            parts.push(format!("wbps={}", v));
        }
        parts.join(" ")
    }
}

/// Resource limits configuration
#[derive(Debug, Clone, Serialize)]
pub struct ResourceLimits {
    /// Memory limit in bytes (None = unlimited)
    pub memory_bytes: Option<u64>,
    /// Memory soft limit in bytes (auto-set to 90% of memory_bytes)
    pub memory_high: Option<u64>,
    /// Swap limit in bytes (Some(0) = disable swap)
    pub memory_swap_max: Option<u64>,
    /// CPU quota in microseconds per period
    pub cpu_quota_us: Option<u64>,
    /// CPU period in microseconds (default: 100000 = 100ms)
    pub cpu_period_us: u64,
    /// CPU scheduling weight (1-10000)
    pub cpu_weight: Option<u64>,
    /// Maximum number of PIDs (None = unlimited)
    pub pids_max: Option<u64>,
    /// Per-device I/O limits
    pub io_limits: Vec<IoDeviceLimit>,
    /// RLIMIT_MEMLOCK in bytes (None = use default 64KB).
    /// io_uring requires a larger limit (e.g. 8M) for ring buffers.
    pub memlock_bytes: Option<u64>,
}

impl ResourceLimits {
    /// Create unlimited resource limits
    pub fn unlimited() -> Self {
        Self {
            memory_bytes: None,
            memory_high: None,
            memory_swap_max: None,
            cpu_quota_us: None,
            cpu_period_us: 100_000, // 100ms default period
            cpu_weight: None,
            pids_max: None,
            io_limits: Vec::new(),
            memlock_bytes: None,
        }
    }

    /// Parse memory limit from string (e.g., "512M", "1G")
    pub fn parse_memory(s: &str) -> Result<u64> {
        let s = s.trim();
        if s.is_empty() {
            return Err(NucleusError::InvalidResourceLimit(
                "Empty memory limit".to_string(),
            ));
        }

        let (num_str, multiplier) = if s.ends_with('K') || s.ends_with('k') {
            (&s[..s.len() - 1], 1024u64)
        } else if s.ends_with('M') || s.ends_with('m') {
            (&s[..s.len() - 1], 1024 * 1024)
        } else if s.ends_with('G') || s.ends_with('g') {
            (&s[..s.len() - 1], 1024 * 1024 * 1024)
        } else if s.ends_with('T') || s.ends_with('t') {
            (&s[..s.len() - 1], 1024 * 1024 * 1024 * 1024)
        } else {
            // No suffix, assume bytes
            (s, 1)
        };

        let num: u64 = num_str.parse().map_err(|_| {
            NucleusError::InvalidResourceLimit(format!("Invalid memory value: {}", s))
        })?;

        num.checked_mul(multiplier).ok_or_else(|| {
            NucleusError::InvalidResourceLimit(format!("Memory value overflows u64: {}", s))
        })
    }

    /// Set memory limit from string (e.g., "512M", "1G")
    ///
    /// Automatically sets memory_high to 90% of the hard limit and
    /// disables swap (memory_swap_max = 0) unless swap was explicitly enabled.
    pub fn with_memory(mut self, limit: &str) -> Result<Self> {
        let bytes = Self::parse_memory(limit)?;
        self.memory_bytes = Some(bytes);
        // Auto-set soft limit to 90% of hard limit (per spec)
        self.memory_high = Some(bytes - bytes / 10);
        // Disable swap by default when memory limit is set
        if self.memory_swap_max.is_none() {
            self.memory_swap_max = Some(0);
        }
        Ok(self)
    }

    /// Enable swap (removes the default swap=0 restriction)
    pub fn with_swap_enabled(mut self) -> Self {
        self.memory_swap_max = None;
        self
    }

    /// Set CPU limit in cores (e.g., 2.5 cores)
    pub fn with_cpu_cores(mut self, cores: f64) -> Result<Self> {
        const MAX_CPU_CORES: f64 = 65_536.0;

        if self.cpu_period_us == 0 {
            return Err(NucleusError::InvalidResourceLimit(
                "CPU period must be greater than 0".to_string(),
            ));
        }
        if cores <= 0.0 || cores.is_nan() || cores.is_infinite() {
            return Err(NucleusError::InvalidResourceLimit(
                "CPU cores must be a finite positive number".to_string(),
            ));
        }
        if cores > MAX_CPU_CORES {
            return Err(NucleusError::InvalidResourceLimit(format!(
                "CPU cores must be <= {}",
                MAX_CPU_CORES
            )));
        }
        // Convert cores to quota: cores * period
        let quota = (cores * self.cpu_period_us as f64) as u64;
        self.cpu_quota_us = Some(quota);
        Ok(self)
    }

    /// Set maximum number of PIDs
    pub fn with_pids(mut self, max_pids: u64) -> Result<Self> {
        if max_pids == 0 {
            return Err(NucleusError::InvalidResourceLimit(
                "Max PIDs must be positive".to_string(),
            ));
        }
        if max_pids == libc::RLIM_INFINITY {
            return Err(NucleusError::InvalidResourceLimit(
                "Max PIDs must be less than RLIM_INFINITY; use 0/None for unlimited".to_string(),
            ));
        }
        self.pids_max = Some(max_pids);
        Ok(self)
    }

    /// Set CPU scheduling weight (1-10000)
    pub fn with_cpu_weight(mut self, weight: u64) -> Result<Self> {
        if !(1..=10000).contains(&weight) {
            return Err(NucleusError::InvalidResourceLimit(
                "CPU weight must be between 1 and 10000".to_string(),
            ));
        }
        self.cpu_weight = Some(weight);
        Ok(self)
    }

    /// Add an I/O device limit
    pub fn with_io_limit(mut self, limit: IoDeviceLimit) -> Self {
        self.io_limits.push(limit);
        self
    }

    /// Set RLIMIT_MEMLOCK (e.g. "8M" for io_uring ring buffers)
    pub fn with_memlock(mut self, limit: &str) -> Result<Self> {
        self.memlock_bytes = Some(Self::parse_memory(limit)?);
        Ok(self)
    }

    /// Validate invariants required by runtime, cgroup, and OCI limit consumers.
    pub fn validate_runtime_sanity(&self) -> Result<()> {
        if self.cpu_period_us == 0 {
            return Err(NucleusError::InvalidResourceLimit(
                "CPU period must be greater than 0".to_string(),
            ));
        }

        if let Some(pids_max) = self.pids_max {
            if pids_max == 0 {
                return Err(NucleusError::InvalidResourceLimit(
                    "Max PIDs must be positive".to_string(),
                ));
            }
            if pids_max == libc::RLIM_INFINITY {
                return Err(NucleusError::InvalidResourceLimit(
                    "Max PIDs must be less than RLIM_INFINITY; use 0/None for unlimited"
                        .to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Return true when at least one cgroup v2 control will be configured.
    pub fn has_cgroup_control(&self) -> bool {
        self.memory_bytes.is_some()
            || self.memory_high.is_some()
            || self.memory_swap_max.is_some()
            || self.cpu_quota_us.is_some()
            || self.cpu_weight.is_some()
            || self.pids_max.is_some()
            || !self.io_limits.is_empty()
    }
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            pids_max: Some(512),
            ..Self::unlimited()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_memory() {
        assert_eq!(ResourceLimits::parse_memory("1024").unwrap(), 1024);
        assert_eq!(ResourceLimits::parse_memory("512K").unwrap(), 512 * 1024);
        assert_eq!(
            ResourceLimits::parse_memory("512M").unwrap(),
            512 * 1024 * 1024
        );
        assert_eq!(
            ResourceLimits::parse_memory("2G").unwrap(),
            2 * 1024 * 1024 * 1024
        );
    }

    #[test]
    fn test_parse_memory_invalid() {
        assert!(ResourceLimits::parse_memory("").is_err());
        assert!(ResourceLimits::parse_memory("abc").is_err());
        assert!(ResourceLimits::parse_memory("M").is_err());
    }

    #[test]
    fn test_parse_memory_overflow_rejected() {
        // 18446744073709551615T would overflow u64
        assert!(ResourceLimits::parse_memory("99999999999999T").is_err());
        // Just under u64::MAX in bytes should work
        assert!(ResourceLimits::parse_memory("16383P").is_err()); // not a valid suffix, treated as bytes
    }

    #[test]
    fn test_with_cpu_cores() {
        let limits = ResourceLimits::unlimited();
        let limits = limits.with_cpu_cores(2.0).unwrap();
        assert_eq!(limits.cpu_quota_us, Some(200_000)); // 2.0 * 100_000
    }

    #[test]
    fn test_with_cpu_cores_fractional() {
        let limits = ResourceLimits::unlimited();
        let limits = limits.with_cpu_cores(0.5).unwrap();
        assert_eq!(limits.cpu_quota_us, Some(50_000)); // 0.5 * 100_000
    }

    #[test]
    fn test_with_cpu_cores_invalid() {
        let limits = ResourceLimits::unlimited();
        assert!(limits.with_cpu_cores(0.0).is_err());
        assert!(ResourceLimits::unlimited().with_cpu_cores(-1.0).is_err());
    }

    #[test]
    fn test_with_cpu_cores_rejects_zero_period() {
        let mut limits = ResourceLimits::unlimited();
        limits.cpu_period_us = 0;
        assert!(limits.with_cpu_cores(1.0).is_err());
    }

    #[test]
    fn test_with_memory_auto_sets_memory_high() {
        let limits = ResourceLimits::unlimited().with_memory("1G").unwrap();
        let expected_bytes = 1024 * 1024 * 1024u64;
        assert_eq!(limits.memory_bytes, Some(expected_bytes));
        // memory_high should be 90% of hard limit
        assert_eq!(
            limits.memory_high,
            Some(expected_bytes - expected_bytes / 10)
        );
    }

    #[test]
    fn test_with_memory_disables_swap_by_default() {
        let limits = ResourceLimits::unlimited().with_memory("512M").unwrap();
        assert_eq!(limits.memory_swap_max, Some(0));
    }

    #[test]
    fn test_swap_enabled_clears_swap_limit() {
        let limits = ResourceLimits::unlimited()
            .with_memory("512M")
            .unwrap()
            .with_swap_enabled();
        assert!(limits.memory_swap_max.is_none());
    }

    #[test]
    fn test_with_cpu_weight_valid() {
        let limits = ResourceLimits::unlimited().with_cpu_weight(100).unwrap();
        assert_eq!(limits.cpu_weight, Some(100));

        let limits = ResourceLimits::unlimited().with_cpu_weight(1).unwrap();
        assert_eq!(limits.cpu_weight, Some(1));

        let limits = ResourceLimits::unlimited().with_cpu_weight(10000).unwrap();
        assert_eq!(limits.cpu_weight, Some(10000));
    }

    #[test]
    fn test_with_cpu_weight_invalid() {
        assert!(ResourceLimits::unlimited().with_cpu_weight(0).is_err());
        assert!(ResourceLimits::unlimited().with_cpu_weight(10001).is_err());
    }

    #[test]
    fn test_with_pids_rejects_rlim_infinity() {
        assert!(ResourceLimits::unlimited()
            .with_pids(libc::RLIM_INFINITY)
            .is_err());
    }

    #[test]
    fn test_io_device_limit_parse_valid() {
        let limit = IoDeviceLimit::parse("8:0 riops=1000 wbps=10485760").unwrap();
        assert_eq!(limit.device, "8:0");
        assert_eq!(limit.riops, Some(1000));
        assert_eq!(limit.wbps, Some(10485760));
        assert!(limit.wiops.is_none());
        assert!(limit.rbps.is_none());
    }

    #[test]
    fn test_io_device_limit_parse_all_params() {
        let limit = IoDeviceLimit::parse("8:0 riops=100 wiops=200 rbps=300 wbps=400").unwrap();
        assert_eq!(limit.riops, Some(100));
        assert_eq!(limit.wiops, Some(200));
        assert_eq!(limit.rbps, Some(300));
        assert_eq!(limit.wbps, Some(400));
    }

    #[test]
    fn test_io_device_limit_parse_invalid() {
        // Empty string
        assert!(IoDeviceLimit::parse("").is_err());
        // Bad device format
        assert!(IoDeviceLimit::parse("bad").is_err());
        assert!(IoDeviceLimit::parse("8:0:1").is_err());
        // Bad param format
        assert!(IoDeviceLimit::parse("8:0 riops").is_err());
        // Unknown param
        assert!(IoDeviceLimit::parse("8:0 foo=100").is_err());
        // Bad value
        assert!(IoDeviceLimit::parse("8:0 riops=abc").is_err());
    }

    #[test]
    fn test_io_device_limit_to_io_max_line() {
        let limit = IoDeviceLimit {
            device: "8:0".to_string(),
            riops: Some(1000),
            wiops: None,
            rbps: None,
            wbps: Some(10485760),
        };
        assert_eq!(limit.to_io_max_line(), "8:0 riops=1000 wbps=10485760");
    }

    #[test]
    fn test_unlimited_defaults() {
        let limits = ResourceLimits::unlimited();
        assert!(limits.memory_bytes.is_none());
        assert!(limits.memory_high.is_none());
        assert!(limits.memory_swap_max.is_none());
        assert!(limits.cpu_quota_us.is_none());
        assert!(limits.cpu_weight.is_none());
        assert!(limits.pids_max.is_none());
        assert!(limits.io_limits.is_empty());
        assert!(!limits.has_cgroup_control());
        assert!(ResourceLimits::default().has_cgroup_control());
    }

    #[test]
    fn test_memory_high_uses_integer_arithmetic() {
        // BUG-13: memory_high must use integer arithmetic, not floating point
        let limits = ResourceLimits::unlimited().with_memory("1G").unwrap();
        let bytes = 1024u64 * 1024 * 1024;
        let expected_high = bytes - bytes / 10; // 90% via integer
        assert_eq!(
            limits.memory_high,
            Some(expected_high),
            "memory_high must be exactly bytes - bytes/10 (integer arithmetic)"
        );
    }

    #[test]
    fn test_cpu_cores_rejects_extreme_values() {
        // BUG-12: Extreme CPU core values must be rejected, not silently overflow
        assert!(ResourceLimits::unlimited()
            .with_cpu_cores(f64::NAN)
            .is_err());
        assert!(ResourceLimits::unlimited()
            .with_cpu_cores(f64::INFINITY)
            .is_err());
        assert!(
            ResourceLimits::unlimited()
                .with_cpu_cores(100_000.0)
                .is_err(),
            "CPU cores > 65536 must be rejected to prevent quota overflow"
        );
    }

    #[test]
    fn test_validate_runtime_sanity_rejects_invalid_deserialized_values() {
        let mut limits = ResourceLimits::unlimited();
        limits.cpu_period_us = 0;
        limits.pids_max = Some(libc::RLIM_INFINITY);

        assert!(limits.validate_runtime_sanity().is_err());
    }
}
