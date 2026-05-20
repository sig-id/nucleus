# Resource Control

## Overview

Nucleus uses Linux cgroup v2 for resource isolation and limiting. Each container runs in its own cgroup with enforced memory, CPU, I/O, and process limits.

Service mode behavior:
- Agent mode treats cgroup setup as best-effort and may continue without limits when cgroup creation fails.
- Strict agent mode requires cgroup creation and successful application of configured limits, but does not require explicit memory or CPU limits beyond the default PID limit.
- Production mode requires cgroup creation, successful limit application, and explicit memory and CPU limits.

## cgroup v2 Hierarchy

```
/sys/fs/cgroup/
└── nucleus/
    ├── nucleus-<container-id-1>/
    │   ├── cgroup.procs
    │   ├── memory.max
    │   ├── memory.high
    │   ├── cpu.max
    │   ├── io.max
    │   └── pids.max
    ├── nucleus-<container-id-2>/
    └── ...
```

## Memory Control

### Configuration

```rust
struct MemoryConfig {
    /// Hard limit - OOM kill if exceeded
    max: Option<u64>,

    /// Soft limit - throttle if exceeded
    high: Option<u64>,

    /// Swap limit (usually disabled)
    swap_max: Option<u64>,
}
```

### Implementation

```rust
fn set_memory_limit(cgroup_path: &Path, limit: u64) -> Result<()> {
    // Set hard limit
    write(cgroup_path.join("memory.max"), limit.to_string())?;

    // Set soft limit to 90% of hard limit
    let soft_limit = (limit as f64 * 0.9) as u64;
    write(cgroup_path.join("memory.high"), soft_limit.to_string())?;

    // Disable swap
    write(cgroup_path.join("memory.swap.max"), "0")?;

    Ok(())
}
```

### Behavior

- **Below memory.high** - Normal operation
- **Above memory.high** - Kernel reclaims memory, slows allocations
- **At memory.max** - OOM killer invoked, container killed

### Monitoring

```rust
fn get_memory_usage(cgroup_path: &Path) -> Result<MemoryStats> {
    let current = read_to_string(cgroup_path.join("memory.current"))?
        .trim()
        .parse()?;

    let max = read_to_string(cgroup_path.join("memory.max"))?
        .trim()
        .parse()?;

    Ok(MemoryStats { current, max })
}
```

## CPU Control

### Configuration

```rust
struct CpuConfig {
    /// CPU bandwidth: (quota_us, period_us)
    /// e.g., (200000, 100000) = 2 cores
    max: Option<(u64, u64)>,

    /// Relative weight (1-10000)
    weight: Option<u64>,
}
```

### Implementation

```rust
fn set_cpu_limit(cgroup_path: &Path, cores: f64) -> Result<()> {
    // Convert cores to quota/period
    // period = 100ms (100000 us)
    // quota = cores * period
    let period = 100_000u64;
    let quota = (cores * period as f64) as u64;

    write(
        cgroup_path.join("cpu.max"),
        format!("{} {}", quota, period)
    )?;

    Ok(())
}
```

### Example

```bash
# Limit to 2.5 cores
echo "250000 100000" > cpu.max

# Every 100ms, process can use 250ms of CPU time
# (2.5 cores of a 100ms period)
```

### CPU Weight

```rust
fn set_cpu_weight(cgroup_path: &Path, weight: u64) -> Result<()> {
    // weight: 1-10000 (default: 100)
    // Higher weight = more CPU share during contention
    write(cgroup_path.join("cpu.weight"), weight.to_string())?;
    Ok(())
}
```

## I/O Control

### Configuration

```rust
struct IoConfig {
    /// Per-device limits
    devices: Vec<IoDeviceLimit>,
}

struct IoDeviceLimit {
    /// Major:minor device number (e.g., "8:0" for /dev/sda)
    device: String,

    /// Read IOPS limit
    riops: Option<u64>,

    /// Write IOPS limit
    wiops: Option<u64>,

    /// Read bandwidth (bytes/sec)
    rbps: Option<u64>,

    /// Write bandwidth (bytes/sec)
    wbps: Option<u64>,
}
```

### Implementation

```rust
fn set_io_limit(cgroup_path: &Path, limit: &IoDeviceLimit) -> Result<()> {
    let mut line = format!("{}", limit.device);

    if let Some(riops) = limit.riops {
        line.push_str(&format!(" riops={}", riops));
    }
    if let Some(wiops) = limit.wiops {
        line.push_str(&format!(" wiops={}", wiops));
    }
    if let Some(rbps) = limit.rbps {
        line.push_str(&format!(" rbps={}", rbps));
    }
    if let Some(wbps) = limit.wbps {
        line.push_str(&format!(" wbps={}", wbps));
    }

    write(cgroup_path.join("io.max"), line)?;
    Ok(())
}
```

### Example

```bash
# Limit /dev/sda to 1000 IOPS and 10MB/s
echo "8:0 riops=1000 wiops=1000 rbps=10485760 wbps=10485760" > io.max
```

## Process Control

### PID Limits

Prevent fork bombs:

```rust
fn set_pids_limit(cgroup_path: &Path, max_pids: u64) -> Result<()> {
    write(cgroup_path.join("pids.max"), max_pids.to_string())?;
    Ok(())
}
```

Default: **1024 processes**

## cgroup Lifecycle

### Creation

```rust
fn create_container_cgroup(container_id: &str) -> Result<PathBuf> {
    let cgroup_path = Path::new("/sys/fs/cgroup/nucleus")
        .join(format!("nucleus-{}", container_id));

    // Ensure parent cgroup exists
    create_dir_all("/sys/fs/cgroup/nucleus")?;

    // Create container cgroup
    create_dir_all(&cgroup_path)?;

    Ok(cgroup_path)
}
```

### Attaching Process

```rust
fn attach_process_to_cgroup(cgroup_path: &Path, pid: u32) -> Result<()> {
    write(cgroup_path.join("cgroup.procs"), pid.to_string())?;
    Ok(())
}
```

### Cleanup

```rust
fn cleanup_cgroup(cgroup_path: &Path) -> Result<()> {
    // Ensure all processes are gone
    let procs = read_to_string(cgroup_path.join("cgroup.procs"))?;
    if !procs.trim().is_empty() {
        // Kill remaining processes
        for pid_str in procs.lines() {
            if let Ok(pid) = pid_str.parse::<i32>() {
                let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
            }
        }
    }

    // Remove cgroup directory
    remove_dir(cgroup_path)?;
    Ok(())
}
```

## Resource Profiles

### Predefined Profiles

```rust
enum ResourceProfile {
    Minimal,   // 128MB RAM, 0.5 CPU, 256 PIDs
    Small,     // 512MB RAM, 1 CPU, 512 PIDs
    Medium,    // 1GB RAM, 2 CPU, 1024 PIDs
    Large,     // 4GB RAM, 4 CPU, 2048 PIDs
    Custom(ResourceConfig),
}

impl ResourceProfile {
    fn to_config(&self) -> ResourceConfig {
        match self {
            Self::Minimal => ResourceConfig {
                memory_max: Some(128 * 1024 * 1024),
                cpu_max: Some((50_000, 100_000)),  // 0.5 cores
                pids_max: Some(256),
                ..Default::default()
            },
            Self::Small => ResourceConfig {
                memory_max: Some(512 * 1024 * 1024),
                cpu_max: Some((100_000, 100_000)),  // 1 core
                pids_max: Some(512),
                ..Default::default()
            },
            // ...
        }
    }
}
```

## Monitoring and Observability

### Real-time Stats

```rust
struct ResourceStats {
    memory: MemoryStats,
    cpu: CpuStats,
    io: IoStats,
    pids: PidStats,
}

struct MemoryStats {
    current: u64,
    max: u64,
    utilization: f64,  // current / max
}

struct CpuStats {
    usage_usec: u64,
    user_usec: u64,
    system_usec: u64,
}

fn collect_stats(cgroup_path: &Path) -> Result<ResourceStats> {
    // Read memory.current, memory.stat
    let memory_current = read_u64(cgroup_path.join("memory.current"))?;
    let memory_max = read_u64(cgroup_path.join("memory.max"))?;

    // Read cpu.stat
    let cpu_stat = read_to_string(cgroup_path.join("cpu.stat"))?;
    let cpu_usage = parse_cpu_stat(&cpu_stat)?;

    // Read io.stat
    let io_stat = read_to_string(cgroup_path.join("io.stat"))?;
    let io = parse_io_stat(&io_stat)?;

    // Read pids.current
    let pids_current = read_u64(cgroup_path.join("pids.current"))?;

    Ok(ResourceStats {
        memory: MemoryStats {
            current: memory_current,
            max: memory_max,
            utilization: memory_current as f64 / memory_max as f64,
        },
        cpu: cpu_usage,
        io,
        pids: PidStats { current: pids_current },
    })
}
```

### Events and Alerts

Monitor for resource pressure:

```rust
fn monitor_memory_pressure(cgroup_path: &Path) -> Result<()> {
    // Read memory.pressure
    let pressure = read_to_string(cgroup_path.join("memory.pressure"))?;
    // Parse PSI (Pressure Stall Information)
    // some avg10=2.00 avg60=1.50 avg300=1.00 total=5000000
    // full avg10=1.00 avg60=0.50 avg300=0.25 total=2000000

    // Trigger alerts if pressure is high
    Ok(())
}
```

## Future Enhancements

1. **Burst allowance** - Short-term overcommit for bursty workloads
2. **QoS classes** - Guaranteed vs best-effort resources
3. **Resource reservations** - Reserve resources before starting
4. **Auto-scaling** - Adjust limits based on utilization
5. **Federated limits** - Coordinate limits across multiple hosts
