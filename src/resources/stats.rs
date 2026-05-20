use crate::error::{NucleusError, Result};
use serde::Serialize;
use std::fs;
use std::path::Path;

/// Resource usage statistics for a container
#[derive(Debug, Clone, Serialize)]
pub struct ResourceStats {
    /// Memory usage in bytes
    pub memory_usage: u64,

    /// Memory limit in bytes (0 = unlimited)
    pub memory_limit: u64,

    /// Swap usage in bytes
    pub memory_swap_usage: u64,

    /// CPU usage in nanoseconds
    pub cpu_usage_ns: u64,

    /// Number of PIDs in the cgroup
    pub pid_count: u64,

    /// Memory usage percentage (0-100)
    pub memory_percent: f64,
}

impl ResourceStats {
    /// Read resource stats from a cgroup path
    pub fn from_cgroup(cgroup_path: &str) -> Result<Self> {
        let cgroup_path = Path::new(cgroup_path);

        // Read memory stats
        let memory_usage = Self::read_memory_current(cgroup_path)?;
        let memory_limit = Self::read_memory_max(cgroup_path)?;

        // Calculate memory percentage
        let memory_percent = if memory_limit > 0 {
            (memory_usage as f64 / memory_limit as f64) * 100.0
        } else {
            0.0
        };

        // Read swap usage
        let memory_swap_usage = Self::read_memory_swap(cgroup_path).unwrap_or(0);

        // Read CPU stats
        let cpu_usage_ns = Self::read_cpu_usage(cgroup_path)?;

        // Read PID stats
        let pid_count = Self::read_pid_current(cgroup_path)?;

        Ok(Self {
            memory_usage,
            memory_limit,
            memory_swap_usage,
            cpu_usage_ns,
            pid_count,
            memory_percent,
        })
    }

    /// Read memory.current (current memory usage)
    fn read_memory_current(cgroup_path: &Path) -> Result<u64> {
        let path = cgroup_path.join("memory.current");
        Self::read_u64_file(&path)
    }

    /// Read memory.max (memory limit)
    fn read_memory_max(cgroup_path: &Path) -> Result<u64> {
        let path = cgroup_path.join("memory.max");
        let content = fs::read_to_string(&path).map_err(|e| {
            NucleusError::ResourceError(format!("Failed to read {:?}: {}", path, e))
        })?;

        // memory.max can be "max" for unlimited
        if content.trim() == "max" {
            Ok(0)
        } else {
            content.trim().parse().map_err(|e| {
                NucleusError::ResourceError(format!("Failed to parse memory.max: {}", e))
            })
        }
    }

    /// Read memory.swap.current (swap usage)
    fn read_memory_swap(cgroup_path: &Path) -> Result<u64> {
        let path = cgroup_path.join("memory.swap.current");
        Self::read_u64_file(&path)
    }

    /// Read cpu.stat (CPU usage)
    fn read_cpu_usage(cgroup_path: &Path) -> Result<u64> {
        let path = cgroup_path.join("cpu.stat");
        let content = fs::read_to_string(&path).map_err(|e| {
            NucleusError::ResourceError(format!("Failed to read {:?}: {}", path, e))
        })?;

        // Parse cpu.stat format:
        // usage_usec 12345
        // user_usec 6789
        // system_usec 5556
        for line in content.lines() {
            if let Some(value_str) = line.strip_prefix("usage_usec ") {
                let usec: u64 = value_str.parse().map_err(|e| {
                    NucleusError::ResourceError(format!("Failed to parse CPU usage: {}", e))
                })?;
                // Convert microseconds to nanoseconds
                return Ok(usec * 1000);
            }
        }

        Err(NucleusError::ResourceError(format!(
            "cpu.stat at {:?} does not contain 'usage_usec' key",
            path
        )))
    }

    /// Read pids.current (current number of PIDs)
    fn read_pid_current(cgroup_path: &Path) -> Result<u64> {
        let path = cgroup_path.join("pids.current");
        Self::read_u64_file(&path)
    }

    /// Read a file containing a single u64 value
    fn read_u64_file(path: &Path) -> Result<u64> {
        let content = fs::read_to_string(path).map_err(|e| {
            NucleusError::ResourceError(format!("Failed to read {:?}: {}", path, e))
        })?;

        content
            .trim()
            .parse()
            .map_err(|e| NucleusError::ResourceError(format!("Failed to parse {:?}: {}", path, e)))
    }

    /// Format memory size in human-readable format
    pub fn format_memory(bytes: u64) -> String {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;

        if bytes >= GB {
            format!("{:.2}G", bytes as f64 / GB as f64)
        } else if bytes >= MB {
            format!("{:.2}M", bytes as f64 / MB as f64)
        } else if bytes >= KB {
            format!("{:.2}K", bytes as f64 / KB as f64)
        } else {
            format!("{}B", bytes)
        }
    }

    /// Format CPU usage in seconds
    pub fn format_cpu_time(ns: u64) -> String {
        let seconds = ns as f64 / 1_000_000_000.0;
        format!("{:.2}s", seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_memory() {
        assert_eq!(ResourceStats::format_memory(512), "512B");
        assert_eq!(ResourceStats::format_memory(1024), "1.00K");
        assert_eq!(ResourceStats::format_memory(1024 * 1024), "1.00M");
        assert_eq!(ResourceStats::format_memory(1024 * 1024 * 1024), "1.00G");
        assert_eq!(ResourceStats::format_memory(512 * 1024 * 1024), "512.00M");
    }

    #[test]
    fn test_format_cpu_time() {
        assert_eq!(ResourceStats::format_cpu_time(0), "0.00s");
        assert_eq!(ResourceStats::format_cpu_time(1_000_000_000), "1.00s");
        assert_eq!(ResourceStats::format_cpu_time(5_500_000_000), "5.50s");
    }
}
