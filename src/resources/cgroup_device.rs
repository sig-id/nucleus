//! cgroup v2 device access control via a `BPF_PROG_TYPE_CGROUP_DEVICE` eBPF program.
//!
//! An exact match on kind, major and minor grants read, write and mknod access.
//! All other devices are denied. See `spec/gpu-passthrough.md`.

use std::fs::OpenOptions;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use tracing::{info, warn};

use crate::error::{NucleusError, Result};

// Linux UAPI <linux/bpf.h>
const BPF_PROG_LOAD: u32 = 5;
const BPF_PROG_ATTACH: u32 = 8;
const BPF_PROG_TYPE_CGROUP_DEVICE: u32 = 15;
const BPF_CGROUP_DEVICE: u32 = 6;
const BPF_F_ALLOW_MULTI: u32 = 2;
const BPF_DEVCG_DEV_BLOCK: u32 = 1;
const BPF_DEVCG_DEV_CHAR: u32 = 2;

/// A single device allowlist entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceAllowSpec {
    pub is_block: bool,
    pub major: u32,
    pub minor: u32,
}

impl DeviceAllowSpec {
    fn device_type(&self) -> u32 {
        if self.is_block {
            BPF_DEVCG_DEV_BLOCK
        } else {
            BPF_DEVCG_DEV_CHAR
        }
    }
}

/// The standard base devices Nucleus creates via `create_dev_nodes`.
///
/// `(is_block, major, minor)`:
/// null(1,3) zero(1,5) full(1,7) random(1,8) urandom(1,9) tty(5,0).
pub fn base_device_specs(include_tty: bool) -> Vec<DeviceAllowSpec> {
    let mut specs = vec![
        DeviceAllowSpec {
            is_block: false,
            major: 1,
            minor: 3,
        }, // null
        DeviceAllowSpec {
            is_block: false,
            major: 1,
            minor: 5,
        }, // zero
        DeviceAllowSpec {
            is_block: false,
            major: 1,
            minor: 7,
        }, // full
        DeviceAllowSpec {
            is_block: false,
            major: 1,
            minor: 8,
        }, // random
        DeviceAllowSpec {
            is_block: false,
            major: 1,
            minor: 9,
        }, // urandom
    ];
    if include_tty {
        specs.push(DeviceAllowSpec {
            is_block: false,
            major: 5,
            minor: 0,
        }); // tty
    }
    specs
}

/// Linux UAPI `struct bpf_insn`. The two register numbers share one byte.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BpfInsn {
    code: u8,
    regs: u8,
    off: i16,
    imm: i32,
}

impl BpfInsn {
    const fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        let regs = if cfg!(target_endian = "little") {
            dst | (src << 4)
        } else {
            (dst << 4) | src
        };
        Self {
            code,
            regs,
            off,
            imm,
        }
    }
}

fn build_device_program(specs: &[DeviceAllowSpec]) -> Vec<BpfInsn> {
    const LDX_W: u8 = 0x61;
    const AND32_IMM: u8 = 0x54;
    const JNE32_IMM: u8 = 0x56;
    const MOV32_IMM: u8 = 0xb4;
    const EXIT: BpfInsn = BpfInsn::new(0x95, 0, 0, 0, 0);

    // R1 points to bpf_cgroup_dev_ctx { u32 access_type, major, minor }.
    // The low 16 bits of access_type contain the device kind. Each listed
    // device grants all three access modes encoded in the high 16 bits.
    let mut prog = vec![
        BpfInsn::new(LDX_W, 2, 1, 0, 0),
        BpfInsn::new(AND32_IMM, 2, 0, 0, 0xffff),
        BpfInsn::new(LDX_W, 3, 1, 4, 0),
        BpfInsn::new(LDX_W, 4, 1, 8, 0),
    ];
    for spec in specs {
        // Each mismatch skips to the next entry (or the final deny).
        prog.extend([
            BpfInsn::new(JNE32_IMM, 2, 0, 4, spec.device_type() as i32),
            BpfInsn::new(JNE32_IMM, 3, 0, 3, spec.major as i32),
            BpfInsn::new(JNE32_IMM, 4, 0, 2, spec.minor as i32),
            BpfInsn::new(MOV32_IMM, 0, 0, 0, 1),
            EXIT,
        ]);
    }
    prog.extend([BpfInsn::new(MOV32_IMM, 0, 0, 0, 0), EXIT]);
    prog
}

// ---- bpf(2) syscall wrappers --------------------------------------------

/// `union bpf_attr` subset for `BPF_PROG_LOAD`.
#[repr(C)]
#[derive(Default)]
struct BpfProgAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
}

/// `union bpf_attr` subset for `BPF_PROG_ATTACH`.
#[repr(C)]
struct BpfAttachAttr {
    target_fd: u32,
    attach_bpf_fd: u32,
    attach_type: u32,
    attach_flags: u32,
}

/// Load and attach a cgroup device allowlist program to the cgroup at `path`.
///
/// Returns `Ok(true)` if the program was attached, `Ok(false)` if it was
/// intentionally skipped (kernel/capability unavailable and `best_effort`),
/// or `Err` on an unexpected failure that callers should treat as fatal.
pub fn install_device_allowlist(
    cgroup_path: &Path,
    specs: &[DeviceAllowSpec],
    best_effort: bool,
) -> Result<bool> {
    if specs.is_empty() {
        return Ok(false);
    }

    let install = || -> Result<()> {
        let cgroup = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(cgroup_path)
            .map_err(|e| NucleusError::CgroupError(format!("open({cgroup_path:?}): {e}")))?;
        let prog = load_device_program(&build_device_program(specs))?;
        attach_program(cgroup.as_raw_fd(), prog.as_raw_fd())
    };
    match install() {
        Ok(()) => {
            info!(
                "Installed cgroup device allowlist ({} devices) at {:?}",
                specs.len(),
                cgroup_path
            );
            Ok(true)
        }
        Err(e) if best_effort => {
            warn!("Continuing without GPU cgroup device allowlist at {cgroup_path:?}: {e}");
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

fn load_device_program(prog: &[BpfInsn]) -> Result<OwnedFd> {
    // A fixed verifier log can cause ENOSPC even for valid programs on older
    // kernels. Request diagnostics only after a load fails.
    try_load_device_program(prog, &mut []).or_else(|err| {
        let mut log = [0u8; 4096];
        try_load_device_program(prog, &mut log).map_err(|_| {
            let end = log.iter().position(|&byte| byte == 0).unwrap_or(log.len());
            let detail = String::from_utf8_lossy(&log[..end]);
            NucleusError::CgroupError(format!("bpf(PROG_LOAD) failed: {err} {detail}"))
        })
    })
}

fn try_load_device_program(prog: &[BpfInsn], log: &mut [u8]) -> std::io::Result<OwnedFd> {
    let attr = BpfProgAttr {
        prog_type: BPF_PROG_TYPE_CGROUP_DEVICE,
        insn_cnt: prog.len() as u32,
        insns: prog.as_ptr() as u64,
        license: c"GPL".as_ptr() as u64,
        expected_attach_type: BPF_CGROUP_DEVICE,
        log_level: u32::from(!log.is_empty()),
        log_size: log.len() as u32,
        log_buf: if log.is_empty() {
            0
        } else {
            log.as_mut_ptr() as u64
        },
        ..Default::default()
    };

    // SAFETY: bpf(2) with BPF_PROG_LOAD reads our repr(C) attr and the insns
    // slice; it returns a new fd or -1. No aliased mutable state is touched.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_LOAD as libc::c_int,
            &attr as *const BpfProgAttr,
            std::mem::size_of::<BpfProgAttr>() as libc::c_int,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a successful BPF_PROG_LOAD returns a new file descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(ret as RawFd) })
}

fn attach_program(cgroup_fd: RawFd, prog_fd: RawFd) -> Result<()> {
    let attr = BpfAttachAttr {
        target_fd: cgroup_fd as u32,
        attach_bpf_fd: prog_fd as u32,
        attach_type: BPF_CGROUP_DEVICE,
        attach_flags: BPF_F_ALLOW_MULTI,
    };
    // SAFETY: bpf(2) with BPF_PROG_ATTACH reads our repr(C) attr.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_ATTACH as libc::c_int,
            &attr as *const BpfAttachAttr,
            std::mem::size_of::<BpfAttachAttr>() as libc::c_int,
        )
    };
    if ret < 0 {
        return Err(NucleusError::CgroupError(format!(
            "bpf(PROG_ATTACH) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_cgroup_requires_explicit_degradation() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        let specs = base_device_specs(false);
        assert!(install_device_allowlist(&missing, &specs, false).is_err());
        assert!(!install_device_allowlist(&missing, &specs, true).unwrap());
    }

    #[test]
    #[ignore = "requires root with cgroup v2 and BPF"]
    fn kernel_enforces_device_allowlist() {
        // Exercise the real verifier and attachment in a disposable cgroup.
        // /dev/zero matches one entry's numbers but has the wrong kind, and
        // differs by exactly one field from each of the character entries.
        let specs = [
            DeviceAllowSpec {
                is_block: true,
                major: 1,
                minor: 5,
            },
            DeviceAllowSpec {
                is_block: false,
                major: 2,
                minor: 5,
            },
            DeviceAllowSpec {
                is_block: false,
                major: 1,
                minor: 3,
            },
        ];
        std::fs::File::open("/dev/zero").unwrap();
        let cgroup = tempfile::Builder::new()
            .prefix("nucleus-test-devices-")
            .tempdir_in("/sys/fs/cgroup")
            .unwrap();
        assert!(install_device_allowlist(cgroup.path(), &specs, false).unwrap());
        let result = std::process::Command::new("sh")
            .args([
                "-ec",
                r#"
                echo 0 > "$1/cgroup.procs"
                (exec 3<>/dev/null)
                if (exec 3</dev/zero); then exit 1; fi
            "#,
                "device-test",
            ])
            .arg(cgroup.path())
            .status()
            .unwrap();
        std::fs::remove_dir(cgroup.path()).unwrap();
        assert!(result.success());
    }

    #[test]
    fn base_specs_match_created_dev_nodes() {
        let specs = base_device_specs(false);
        let as_pairs: Vec<(u32, u32)> = specs.iter().map(|s| (s.major, s.minor)).collect();
        assert_eq!(as_pairs, vec![(1, 3), (1, 5), (1, 7), (1, 8), (1, 9)]);
        let with_tty = base_device_specs(true);
        assert_eq!(with_tty.len(), 6);
        assert!(with_tty.iter().any(|s| s.major == 5 && s.minor == 0));
    }

    #[test]
    fn block_device_uses_block_type() {
        let spec = DeviceAllowSpec {
            is_block: true,
            major: 8,
            minor: 0,
        };
        assert_eq!(spec.device_type(), BPF_DEVCG_DEV_BLOCK);
        let char_spec = DeviceAllowSpec {
            is_block: false,
            major: 1,
            minor: 3,
        };
        assert_eq!(char_spec.device_type(), BPF_DEVCG_DEV_CHAR);
    }
}
