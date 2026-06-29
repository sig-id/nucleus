//! cgroup v2 device access control via a `BPF_PROG_TYPE_CGROUP_DEVICE` program.
//!
//! cgroup v2 has no `devices` controller file; device access is gated by a
//! classic-BPF (cBPF) program attached to the cgroup. Without one, the default
//! is allow-all — which is today's Nucleus behavior. When GPU passthrough is
//! enabled we install an explicit allowlist so a compromised workload cannot
//! reach host devices other than the (minimal) base + GPU set, even if it
//! somehow creates a device node.
//!
//! The bytecode generator is pure and unit-tested; the `bpf(2)` load/attach
//! path is best-effort and degrades to a warning when the kernel or the
//! caller's capabilities do not permit it.
//!
//! See `spec/gpu-passthrough.md` for the design.

use std::mem::MaybeUninit;
use std::os::unix::io::RawFd;
use std::path::Path;

use tracing::{debug, info, warn};

use crate::error::{NucleusError, Result};

// ---- Kernel constants (linux/bpf.h + linux/cgroup_def.h) -----------------

/// `bpf(2)` command: load a program.
const BPF_PROG_LOAD: u32 = 5;
/// `bpf(2)` command: attach a program to a cgroup.
const BPF_PROG_ATTACH: u32 = 8;

/// Program type: cgroup device filter (classic BPF).
const BPF_PROG_TYPE_CGROUP_DEVICE: u32 = 9;

/// Attach type for cgroup device programs.
const BPF_CGROUP_DEVICE: u32 = 6;

/// Device kinds in `bpf_cgroup_dev_ctx.type`.
const BPF_DEVCG_DEV_CHAR: u32 = 1;
const BPF_DEVCG_DEV_BLOCK: u32 = 2;

/// Access bits in `bpf_cgroup_dev_ctx.access`.
const DEV_READ: u32 = 1 << 0;
const DEV_WRITE: u32 = 1 << 1;
const DEV_MKNOD: u32 = 1 << 2;
/// Full rwm access — what we grant to base + GPU devices.
const DEV_ACCESS_ALL: u32 = DEV_READ | DEV_WRITE | DEV_MKNOD;

// Classic BPF opcodes (linux/filter.h), pre-combined to avoid clippy's
// `eq_op`/`no_effect` lints on literal bitwise-OR of constants.
//   BPF_LD   = 0x00  BPF_W = 0x00  BPF_ABS = 0x20
//   BPF_JMP  = 0x05  BPF_JEQ  = 0x10  BPF_JSET = 0x40  BPF_K = 0x00
//   BPF_RET  = 0x06
const BPF_LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
const BPF_JMP_JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
const BPF_JMP_JSET_K: u16 = 0x45; // BPF_JMP | BPF_JSET | BPF_K
const BPF_RET_K: u16 = 0x06; // BPF_RET | BPF_K

/// Return values for the device program: 1 = allow, 0 = deny.
const ALLOW: u32 = 1;
const DENY: u32 = 0;

/// Offsets into `struct bpf_cgroup_dev_ctx` (all `__u32`).
const OFF_ACCESS: u32 = 0;
const OFF_TYPE: u32 = 4;
const OFF_MAJOR: u32 = 8;
const OFF_MINOR: u32 = 12;

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
        DeviceAllowSpec { is_block: false, major: 1, minor: 3 },  // null
        DeviceAllowSpec { is_block: false, major: 1, minor: 5 },  // zero
        DeviceAllowSpec { is_block: false, major: 1, minor: 7 },  // full
        DeviceAllowSpec { is_block: false, major: 1, minor: 8 },  // random
        DeviceAllowSpec { is_block: false, major: 1, minor: 9 },  // urandom
    ];
    if include_tty {
        specs.push(DeviceAllowSpec { is_block: false, major: 5, minor: 0 }); // tty
    }
    specs
}

/// A classic BPF instruction (`struct sock_filter`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

impl SockFilter {
    const fn ld_abs(off: u32) -> Self {
        Self { code: BPF_LD_W_ABS, jt: 0, jf: 0, k: off }
    }
    const fn jeq_k(k: u32, jt: u8, jf: u8) -> Self {
        Self { code: BPF_JMP_JEQ_K, jt, jf, k }
    }
    const fn jset_k(k: u32, jt: u8, jf: u8) -> Self {
        Self { code: BPF_JMP_JSET_K, jt, jf, k }
    }
    const fn ret_k(k: u32) -> Self {
        Self { code: BPF_RET_K, jt: 0, jf: 0, k }
    }
}

/// Number of instructions emitted per allowlist entry (see [`build_device_program`]).
const ENTRY_LEN: usize = 9;

/// Compile the cBPF device program for the given specs.
///
/// Layout per entry (uniform 9 instructions so jump offsets are constant):
/// ```text
///  0 LD   type
///  1 JEQ  type, jt=0, jf=7        (jf -> next entry)
///  2 LD   major
///  3 JEQ  major, jt=0, jf=5
///  4 LD   minor
///  5 JEQ  minor, jt=0, jf=3
///  6 LD   access
///  7 JSET access_all, jt=0, jf=1  (jt -> allow)
///  8 RET  ALLOW
/// ```
/// A trailing `RET DENY` makes the program deny-by-default.
pub(crate) fn build_device_program(specs: &[DeviceAllowSpec]) -> Vec<SockFilter> {
    let mut prog = Vec::with_capacity(specs.len() * ENTRY_LEN + 1);
    for spec in specs {
        prog.push(SockFilter::ld_abs(OFF_TYPE));
        prog.push(SockFilter::jeq_k(spec.device_type(), 0, 7));
        prog.push(SockFilter::ld_abs(OFF_MAJOR));
        prog.push(SockFilter::jeq_k(spec.major, 0, 5));
        prog.push(SockFilter::ld_abs(OFF_MINOR));
        prog.push(SockFilter::jeq_k(spec.minor, 0, 3));
        prog.push(SockFilter::ld_abs(OFF_ACCESS));
        prog.push(SockFilter::jset_k(DEV_ACCESS_ALL, 0, 1));
        prog.push(SockFilter::ret_k(ALLOW));
    }
    prog.push(SockFilter::ret_k(DENY));
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

    let prog = build_device_program(specs);
    debug!(
        "cgroup device program: {} entries, {} instructions",
        specs.len(),
        prog.len()
    );

    let prog_fd = match load_device_program(&prog, best_effort) {
        Ok(fd) => fd,
        Err(e) => {
            if best_effort {
                warn!(
                    "Failed to load cgroup device BPF (continuing without device allowlist): {}",
                    e
                );
                return Ok(false);
            }
            return Err(NucleusError::CgroupError(format!(
                "Failed to load cgroup device BPF: {}",
                e
            )));
        }
    };

    let cgroup_fd = match open_cgroup(cgroup_path) {
        Ok(fd) => fd,
        Err(e) => {
            close_fd(prog_fd);
            if best_effort {
                warn!("Failed to open cgroup for device BPF attach: {}", e);
                return Ok(false);
            }
            return Err(NucleusError::CgroupError(format!(
                "Failed to open cgroup {:?}: {}",
                cgroup_path, e
            )));
        }
    };

    let attached = match attach_program(cgroup_fd, prog_fd) {
        Ok(()) => true,
        Err(e) => {
            if best_effort {
                warn!(
                    "Failed to attach cgroup device BPF (continuing without device allowlist): {}",
                    e
                );
                false
            } else {
                close_fd(prog_fd);
                close_fd(cgroup_fd);
                return Err(NucleusError::CgroupError(format!(
                    "Failed to attach cgroup device BPF: {}",
                    e
                )));
            }
        }
    };

    // attach holds a reference; close our copies.
    close_fd(prog_fd);
    close_fd(cgroup_fd);

    if attached {
        info!(
            "Installed cgroup device allowlist ({} devices) at {:?}",
            specs.len(),
            cgroup_path
        );
    }
    Ok(attached)
}

fn load_device_program(prog: &[SockFilter], best_effort: bool) -> Result<RawFd> {
    // SAFETY: MaybeUninit<sock_filter> has the same layout as our SockFilter
    // (repr(Rust) vs C, but fields are u16,u8,u8,u32 with no padding
    // differences for this layout). We transmute the slice to the kernel's
    // expected representation. sock_filter is { u16 code; u8 jt; u8 jf; u32 k; }.
    let license = b"GPL\0";
    let mut log_buf = vec![0u8; 4096];
    let attr = BpfProgAttr {
        prog_type: BPF_PROG_TYPE_CGROUP_DEVICE,
        insn_cnt: prog.len() as u32,
        insns: prog.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: if best_effort { 0 } else { 1 },
        log_size: log_buf.len() as u32,
        log_buf: log_buf.as_mut_ptr() as u64,
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
        let err = std::io::Error::last_os_error();
        if !log_buf.is_empty() && log_buf[0] != 0 {
            let msg = String::from_utf8_lossy(&log_buf);
            return Err(NucleusError::CgroupError(format!(
                "bpf(PROG_LOAD) failed: {} ({})",
                err,
                msg.trim_end_matches('\0')
            )));
        }
        return Err(NucleusError::CgroupError(format!(
            "bpf(PROG_LOAD) failed: {}",
            err
        )));
    }
    Ok(ret as RawFd)
}

fn open_cgroup(path: &Path) -> Result<RawFd> {
    let cstr = std::ffi::CString::new(path.to_string_lossy().to_string()).map_err(|e| {
        NucleusError::CgroupError(format!("cgroup path contained NUL: {}", e))
    })?;
    // SAFETY: open(2) on a NUL-terminated path; returns fd or -1.
    let fd = unsafe {
        libc::open(
            cstring_ptr(&cstr),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(NucleusError::CgroupError(format!(
            "open({:?}) failed: {}",
            path,
            std::io::Error::last_os_error()
        )));
    }
    Ok(fd)
}

fn attach_program(cgroup_fd: RawFd, prog_fd: RawFd) -> Result<()> {
    let attr = BpfAttachAttr {
        target_fd: cgroup_fd as u32,
        attach_bpf_fd: prog_fd as u32,
        attach_type: BPF_CGROUP_DEVICE,
        attach_flags: 0,
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

fn close_fd(fd: RawFd) {
    if fd >= 0 {
        // SAFETY: close(2) on a valid fd.
        unsafe { libc::close(fd) };
    }
}

/// Reborrow a `CString` as a pointer without consuming it.
///
/// Kept tiny so the `open_cgroup` safety argument stays local.
fn cstring_ptr(c: &std::ffi::CString) -> *const libc::c_char {
    c.as_ptr()
}

// Suppress unused import warning when the MaybeUninit import is not needed.
#[allow(dead_code)]
fn _use_maybeuninit() -> MaybeUninit<u8> {
    MaybeUninit::uninit()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_is_deny_by_default_when_empty() {
        let prog = build_device_program(&[]);
        assert_eq!(prog.len(), 1);
        assert_eq!(prog[0], SockFilter::ret_k(DENY));
    }

    #[test]
    fn each_entry_is_nine_instructions_uniform() {
        let specs = base_device_specs(true);
        let prog = build_device_program(&specs);
        assert_eq!(prog.len(), specs.len() * ENTRY_LEN + 1);

        // Final instruction is always RET DENY.
        assert_eq!(prog.last().copied(), Some(SockFilter::ret_k(DENY)));

        // Verify the layout of the first entry precisely.
        let e = &specs[0];
        assert_eq!(prog[0], SockFilter::ld_abs(OFF_TYPE));
        assert_eq!(prog[1], SockFilter::jeq_k(e.device_type(), 0, 7));
        assert_eq!(prog[2], SockFilter::ld_abs(OFF_MAJOR));
        assert_eq!(prog[3], SockFilter::jeq_k(e.major, 0, 5));
        assert_eq!(prog[4], SockFilter::ld_abs(OFF_MINOR));
        assert_eq!(prog[5], SockFilter::jeq_k(e.minor, 0, 3));
        assert_eq!(prog[6], SockFilter::ld_abs(OFF_ACCESS));
        assert_eq!(prog[7], SockFilter::jset_k(DEV_ACCESS_ALL, 0, 1));
        assert_eq!(prog[8], SockFilter::ret_k(ALLOW));
    }

    #[test]
    fn jump_offsets_reach_next_entry() {
        // With two entries, the first entry's jf jumps must land at the start
        // of the second entry (index ENTRY_LEN), not the final RET.
        let specs = vec![
            DeviceAllowSpec { is_block: false, major: 195, minor: 0 },
            DeviceAllowSpec { is_block: false, major: 226, minor: 128 },
        ];
        let prog = build_device_program(&specs);
        assert_eq!(prog.len(), 2 * ENTRY_LEN + 1);
        // prog[1] jf=7 means from PC=2 jump 7 -> PC=9 = start of entry 2.
        assert_eq!(prog[1].jf, 7);
        // entry 2 starts at index 9: its LD type.
        assert_eq!(prog[ENTRY_LEN], SockFilter::ld_abs(OFF_TYPE));
        // And the final RET DENY sits after entry 2.
        assert_eq!(prog[2 * ENTRY_LEN], SockFilter::ret_k(DENY));
    }

    #[test]
    fn base_specs_match_created_dev_nodes() {
        let specs = base_device_specs(false);
        let as_pairs: Vec<(u32, u32)> = specs.iter().map(|s| (s.major, s.minor)).collect();
        assert_eq!(
            as_pairs,
            vec![(1, 3), (1, 5), (1, 7), (1, 8), (1, 9)]
        );
        let with_tty = base_device_specs(true);
        assert_eq!(with_tty.len(), 6);
        assert!(with_tty.iter().any(|s| s.major == 5 && s.minor == 0));
    }

    #[test]
    fn block_device_uses_block_type() {
        let spec = DeviceAllowSpec { is_block: true, major: 8, minor: 0 };
        assert_eq!(spec.device_type(), BPF_DEVCG_DEV_BLOCK);
        let char_spec = DeviceAllowSpec { is_block: false, major: 1, minor: 3 };
        assert_eq!(char_spec.device_type(), BPF_DEVCG_DEV_CHAR);
    }
}
