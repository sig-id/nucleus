#[cfg(any(target_arch = "x86_64", target_arch = "riscv64"))]
pub(super) const SYS_FADVISE64: i64 = libc::SYS_fadvise64;
#[cfg(any(target_arch = "x86_64", target_arch = "riscv64"))]
pub(super) const SYS_SENDFILE: i64 = libc::SYS_sendfile;

// Linux/aarch64 has these generic syscalls, but libc 0.2.x does not expose
// SYS_fadvise64 or SYS_sendfile constants for that target.
#[cfg(target_arch = "aarch64")]
pub(super) const SYS_FADVISE64: i64 = 223;
#[cfg(target_arch = "aarch64")]
pub(super) const SYS_SENDFILE: i64 = 71;

#[cfg(all(
    test,
    any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )
))]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn generic_file_syscalls_have_current_arch_numbers() {
        assert!(SYS_FADVISE64 > 0);
        assert!(SYS_SENDFILE > 0);
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn aarch64_generic_file_syscalls_match_kernel_table() {
        assert_eq!(SYS_SENDFILE, 71);
        assert_eq!(SYS_FADVISE64, 223);
    }
}
