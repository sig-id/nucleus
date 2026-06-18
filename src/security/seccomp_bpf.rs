//! Bitmap-based BPF compiler for seccomp filters.
//!
//! Replaces seccompiler's default linear-scan BPF generation with a bitmap
//! lookup that resolves unconditional syscall allows in O(1) – a constant
//! ~10 BPF instructions regardless of allowlist size.
//!
//! Program structure:
//!
//! 1. Arch validation (3 insns)
//! 2. Compute bit_position = nr & 31 → M\[0\], word_index = nr >> 5 (5 insns)
//! 3. Dispatch on word_index → load 32-bit bitmap constant (≤46 insns)
//! 4. Bitmap test: `(bitmap >> bit_position) & 1` → ALLOW if set (5 insns)
//! 5. Arg-filtered syscall chains for conditional rules (variable)
//! 6. Default deny
//!
//! Hot path for unconditional allows: ~15 instructions (vs ~120+ for linear scan).

use crate::error::{NucleusError, Result};
use seccompiler::{sock_filter, BpfProgram, SeccompAction, SeccompRule, TargetArch};
use std::collections::BTreeMap;

// --- cBPF constants (pub(crate) in seccompiler, redefined here) ---

const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_ST: u16 = 0x02;
const BPF_ALU: u16 = 0x04;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;

const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_IMM: u16 = 0x00;
const BPF_MEM: u16 = 0x60;

const BPF_AND: u16 = 0x50;
const BPF_RSH: u16 = 0x70;

const BPF_JA: u16 = 0x00;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_X: u16 = 0x08;

const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

const BPF_MAX_LEN: usize = 4096;

// Architecture audit values from linux/audit.h
const AUDIT_ARCH_X86_64: u32 = 62 | 0x8000_0000 | 0x4000_0000;
const AUDIT_ARCH_AARCH64: u32 = 183 | 0x8000_0000 | 0x4000_0000;
const AUDIT_ARCH_RISCV64: u32 = 243 | 0x8000_0000 | 0x4000_0000;

fn arch_audit_value(arch: TargetArch) -> u32 {
    match arch {
        TargetArch::x86_64 => AUDIT_ARCH_X86_64,
        TargetArch::aarch64 => AUDIT_ARCH_AARCH64,
        TargetArch::riscv64 => AUDIT_ARCH_RISCV64,
    }
}

/// Number of 32-bit bitmap words. Covers syscall numbers 0..NUM_BITMAP_WORDS*32-1.
/// x86_64 syscalls go up to ~467, so 15 words (0..479) is sufficient.
const NUM_BITMAP_WORDS: usize = 15;

/// Scratch memory slot for bit_position.
const M_BIT_POS: u32 = 0;

#[inline(always)]
fn bpf_stmt(code: u16, k: u32) -> sock_filter {
    sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

#[inline(always)]
fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

/// Compile a seccomp BPF program using bitmap lookup for O(1) dispatch.
///
/// Rules with empty `Vec<SeccompRule>` are unconditional allows, encoded as
/// bits in a 15-word bitmap (covering syscall numbers 0..479). Rules with
/// non-empty conditions go through a short linear scan of arg-check chains
/// (typically ~7 syscalls).
///
/// The generated program is semantically equivalent to seccompiler's linear
/// scan but executes in O(1) for the common case of unconditional allows.
#[cfg(test)]
fn compile_bitmap_bpf(
    rules: BTreeMap<i64, Vec<SeccompRule>>,
    mismatch_action: SeccompAction,
    match_action: SeccompAction,
    target_arch: TargetArch,
) -> Result<BpfProgram> {
    compile_bitmap_bpf_with_errno_syscalls(rules, &[], mismatch_action, match_action, target_arch)
}

/// Compile a seccomp BPF program with exact-match syscall errno overrides.
///
/// `errno_syscalls` are checked before both the unconditional allow bitmap and
/// the argument-filtered chains. This lets the policy return ENOSYS for syscalls
/// such as clone3, where libc can safely fall back to an older syscall that the
/// filter can inspect.
pub fn compile_bitmap_bpf_with_errno_syscalls(
    rules: BTreeMap<i64, Vec<SeccompRule>>,
    errno_syscalls: &[(i64, u32)],
    mismatch_action: SeccompAction,
    match_action: SeccompAction,
    target_arch: TargetArch,
) -> Result<BpfProgram> {
    let mismatch_val: u32 = mismatch_action.into();
    let match_val: u32 = match_action.into();
    let audit_arch = arch_audit_value(target_arch);
    let errno_actions: Vec<(u32, u32)> = errno_syscalls
        .iter()
        .filter_map(|(nr, errno)| {
            if *nr < 0 || *nr > u32::MAX as i64 {
                None
            } else {
                Some((*nr as u32, SeccompAction::Errno(*errno).into()))
            }
        })
        .collect();

    // Separate unconditional allows (bitmap) from arg-filtered (linear scan).
    let mut bitmap: [u32; NUM_BITMAP_WORDS] = [0; NUM_BITMAP_WORDS];
    let mut arg_filtered: Vec<(i64, Vec<SeccompRule>)> = Vec::new();

    for (nr, chain) in rules {
        if nr < 0 {
            continue;
        }
        if chain.is_empty() {
            let word_idx = (nr >> 5) as usize;
            if word_idx < NUM_BITMAP_WORDS {
                bitmap[word_idx] |= 1u32 << (nr & 31);
            }
        } else {
            arg_filtered.push((nr, chain));
        }
    }

    // Build arg section first – we need its size for dispatch jump offsets.
    let arg_section = build_arg_section(arg_filtered, mismatch_val, match_val);

    // Only emit dispatch entries for non-zero bitmap words.
    let active_words: Vec<(usize, u32)> = bitmap
        .iter()
        .enumerate()
        .filter(|(_, &w)| w != 0)
        .map(|(i, &w)| (i, w))
        .collect();
    let dispatch_entry_count = active_words.len();
    // Each active word: JEQ + LD IMM + JA = 3 insns. Plus 1 for the out-of-range JA.
    let dispatch_len = dispatch_entry_count * 3 + 1;
    let test_len: usize = 5; // LDX M[0]; RSH X; AND 1; JEQ; RET

    let mut prog: BpfProgram = Vec::with_capacity(64 + arg_section.len());

    // === Section 1: Architecture validation ===
    prog.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET));
    prog.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, audit_arch, 1, 0));
    prog.push(bpf_stmt(BPF_RET | BPF_K, libc::SECCOMP_RET_KILL_PROCESS));

    // === Section 1b: Exact-match errno denies ===
    if !errno_actions.is_empty() {
        prog.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));
        for (nr, action) in errno_actions {
            prog.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
            prog.push(bpf_stmt(BPF_RET | BPF_K, action));
        }
    }

    // === Section 2: Setup ===
    // Compute bit_position = nr & 31, save in M[0].
    // Compute word_index = nr >> 5 into A.
    prog.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET)); // A = nr
    prog.push(bpf_stmt(BPF_ALU | BPF_AND | BPF_K, 31)); // A = nr & 31
    prog.push(bpf_stmt(BPF_ST, M_BIT_POS)); // M[0] = bit_pos
    prog.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET)); // A = nr
    prog.push(bpf_stmt(BPF_ALU | BPF_RSH | BPF_K, 5)); // A = word_index

    // === Section 3: Dispatch on word_index ===
    //
    // For each non-zero bitmap word i:
    //   JEQ i, jt=0, jf=2   →  if match, fall through to LD; else skip 2
    //   LD IMM bitmap[i]
    //   JA test_offset       →  jump to bitmap test section
    //
    // After all entries:
    //   JA arg_offset        →  word_index not in bitmap; skip to arg section

    let test_start = dispatch_len; // offset from dispatch start to test section
    for (entry_idx, &(word_idx, word_val)) in active_words.iter().enumerate() {
        let insn_pos = entry_idx * 3; // position within dispatch block
        prog.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, word_idx as u32, 0, 2));
        prog.push(bpf_stmt(BPF_LD | BPF_IMM, word_val));
        let ja_offset = test_start - insn_pos - 3; // distance from JA to test start
        prog.push(bpf_stmt(BPF_JMP | BPF_JA, ja_offset as u32));
    }
    // Out-of-range: jump past test section to arg section (or default deny).
    prog.push(bpf_stmt(BPF_JMP | BPF_JA, test_len as u32));

    // === Section 4: Bitmap test ===
    //
    // X = M[0] (bit_position)
    // A = bitmap_word >> X
    // A = A & 1
    // if A == 1: return ALLOW
    // else: fall through to arg section
    prog.push(bpf_stmt(BPF_LDX | BPF_MEM, M_BIT_POS));
    prog.push(bpf_stmt(BPF_ALU | BPF_RSH | BPF_X, 0));
    prog.push(bpf_stmt(BPF_ALU | BPF_AND | BPF_K, 1));
    prog.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 1)); // bit set → RET
    prog.push(bpf_stmt(BPF_RET | BPF_K, match_val)); // ALLOW

    // === Section 5: Arg-filtered syscall chains ===
    prog.extend(arg_section);

    // === Section 6: Default deny ===
    prog.push(bpf_stmt(BPF_RET | BPF_K, mismatch_val));

    if prog.len() >= BPF_MAX_LEN {
        return Err(NucleusError::SeccompError(format!(
            "BPF program too large: {} instructions (max {})",
            prog.len(),
            BPF_MAX_LEN
        )));
    }

    Ok(prog)
}

/// Build the arg-filtered section: a linear scan of syscalls that need
/// argument-level checks (e.g. clone namespace flags, ioctl request codes).
///
/// Each chain is structured as:
///   JEQ nr, match: skip next JA
///   JA next syscall chain
///   rule chain
///   RET mismatch
///
/// On syscall mismatch, jump over the whole argument-filtered chain directly
/// (preserving A = nr for the next JEQ). Do not route the mismatch path through
/// `SeccompRule`'s internal rule-failure entries; those entries are an
/// implementation detail of seccompiler's rule translation.
fn build_arg_section(
    arg_filtered: Vec<(i64, Vec<SeccompRule>)>,
    mismatch_val: u32,
    match_val: u32,
) -> BpfProgram {
    if arg_filtered.is_empty() {
        return Vec::new();
    }

    let mut section = Vec::new();
    // Reload nr – the bitmap test section clobbered A and X.
    section.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));

    for (syscall_nr, chain) in arg_filtered {
        build_syscall_chain(syscall_nr, chain, mismatch_val, match_val, &mut section);
    }

    section
}

/// Build a single syscall's rule chain.
///
/// Uses `SeccompRule::into::<BpfProgram>()` to generate argument-check BPF
/// for each rule, preserving the existing jump-chain semantics.
fn build_syscall_chain(
    syscall_nr: i64,
    chain: Vec<SeccompRule>,
    mismatch_val: u32,
    match_val: u32,
    out: &mut BpfProgram,
) {
    // Convert each rule to BPF and append RET match_action.
    let chain_bpf: Vec<BpfProgram> = chain
        .into_iter()
        .map(|rule| {
            let mut bpf: BpfProgram = rule.into();
            bpf.push(bpf_stmt(BPF_RET | BPF_K, match_val));
            bpf
        })
        .collect();

    let chain_len: usize = if chain_bpf.is_empty() {
        1 // RET match_action for the unconditional case below.
    } else {
        chain_bpf.iter().map(Vec::len).sum()
    };

    // Chain header: check syscall number.
    // matched: skip the mismatch JA and enter this syscall's rule body.
    // mismatched: jump over this syscall's rule body and mismatch RET.
    out.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, syscall_nr as u32, 1, 0));
    out.push(bpf_stmt(BPF_JMP | BPF_JA, (chain_len + 1) as u32));

    if chain_bpf.is_empty() {
        // Unconditional allow (shouldn't normally reach here from bitmap path,
        // but handle for correctness with custom profiles).
        out.push(bpf_stmt(BPF_RET | BPF_K, match_val));
    } else {
        for mut rule_bpf in chain_bpf {
            out.append(&mut rule_bpf);
        }
    }

    // All rules failed for this syscall → deny.
    out.push(bpf_stmt(BPF_RET | BPF_K, mismatch_val));
}

#[cfg(test)]
mod tests {
    use super::*;
    use seccompiler::{SeccompCmpArgLen, SeccompCmpOp, SeccompCondition};

    const AUDIT_ARCH_X86_64: u32 = 62 | 0x8000_0000 | 0x4000_0000;

    /// Minimal software BPF interpreter for testing seccomp programs.
    fn bpf_eval(prog: &[sock_filter], data: &[u8]) -> u32 {
        let mut a: u32 = 0;
        let mut x: u32 = 0;
        let mut mem: [u32; 16] = [0; 16];
        let mut pc: usize = 0;

        for _ in 0..10_000 {
            // Safety limit
            if pc >= prog.len() {
                panic!("BPF: fell off end of program at pc={}", pc);
            }
            let insn = &prog[pc];
            match insn.code {
                0x00 => {
                    // BPF_LD | BPF_IMM: A = k
                    a = insn.k;
                    pc += 1;
                }
                0x20 => {
                    // BPF_LD | BPF_W | BPF_ABS: A = *(u32*)(data + k)
                    let off = insn.k as usize;
                    a = u32::from_ne_bytes(data[off..off + 4].try_into().unwrap());
                    pc += 1;
                }
                0x60 => {
                    // BPF_LD | BPF_MEM: A = M[k]
                    a = mem[insn.k as usize];
                    pc += 1;
                }
                0x61 => {
                    // BPF_LDX | BPF_MEM: X = M[k]
                    x = mem[insn.k as usize];
                    pc += 1;
                }
                0x02 => {
                    // BPF_ST: M[k] = A
                    mem[insn.k as usize] = a;
                    pc += 1;
                }
                0x54 => {
                    // BPF_ALU | BPF_AND | BPF_K: A &= k
                    a &= insn.k;
                    pc += 1;
                }
                0x74 => {
                    // BPF_ALU | BPF_RSH | BPF_K: A >>= k
                    a >>= insn.k;
                    pc += 1;
                }
                0x7c => {
                    // BPF_ALU | BPF_RSH | BPF_X: A >>= X
                    a = a.checked_shr(x).unwrap_or(0);
                    pc += 1;
                }
                0x05 => {
                    // BPF_JMP | BPF_JA: pc += k
                    pc += 1 + insn.k as usize;
                }
                0x15 => {
                    // BPF_JMP | BPF_JEQ | BPF_K
                    if a == insn.k {
                        pc += 1 + insn.jt as usize;
                    } else {
                        pc += 1 + insn.jf as usize;
                    }
                }
                0x25 => {
                    // BPF_JMP | BPF_JGT | BPF_K
                    if a > insn.k {
                        pc += 1 + insn.jt as usize;
                    } else {
                        pc += 1 + insn.jf as usize;
                    }
                }
                0x35 => {
                    // BPF_JMP | BPF_JGE | BPF_K
                    if a >= insn.k {
                        pc += 1 + insn.jt as usize;
                    } else {
                        pc += 1 + insn.jf as usize;
                    }
                }
                0x06 => {
                    // BPF_RET | BPF_K: return k
                    return insn.k;
                }
                0x07 => {
                    // BPF_MISC | BPF_TAX: X = A
                    x = a;
                    pc += 1;
                }
                other => panic!("BPF: unknown opcode 0x{:04x} at pc={}", other, pc),
            }
        }
        panic!("BPF: execution limit exceeded");
    }

    /// Build a seccomp_data byte array for testing.
    fn make_seccomp_data(nr: u32, arch: u32, args: [u64; 6]) -> Vec<u8> {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&nr.to_ne_bytes());
        data[4..8].copy_from_slice(&arch.to_ne_bytes());
        // instruction_pointer at offset 8 (zeroed)
        for (i, arg) in args.iter().enumerate() {
            let offset = 16 + i * 8;
            data[offset..offset + 8].copy_from_slice(&arg.to_ne_bytes());
        }
        data
    }

    const RET_ALLOW: u32 = 0x7fff_0000; // SECCOMP_RET_ALLOW
    const RET_KILL: u32 = 0x8000_0000; // SECCOMP_RET_KILL_PROCESS
    const RET_ERRNO_ENOSYS: u32 = libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32;

    #[test]
    fn test_unconditional_allows() {
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        rules.insert(0, Vec::new()); // read
        rules.insert(1, Vec::new()); // write
        rules.insert(2, Vec::new()); // open
        rules.insert(60, Vec::new()); // exit
        rules.insert(231, Vec::new()); // exit_group

        let prog = compile_bitmap_bpf(
            rules,
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .unwrap();

        // Allowed syscalls should return ALLOW
        for nr in [0, 1, 2, 60, 231] {
            let data = make_seccomp_data(nr, AUDIT_ARCH_X86_64, [0; 6]);
            assert_eq!(
                bpf_eval(&prog, &data),
                RET_ALLOW,
                "syscall {} should be allowed",
                nr
            );
        }

        // Disallowed syscalls should return KILL
        for nr in [3, 4, 59, 100, 300] {
            let data = make_seccomp_data(nr, AUDIT_ARCH_X86_64, [0; 6]);
            assert_eq!(
                bpf_eval(&prog, &data),
                RET_KILL,
                "syscall {} should be killed",
                nr
            );
        }
    }

    #[test]
    fn test_errno_syscall_overrides_unconditional_allow() {
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        rules.insert(0, Vec::new()); // read
        rules.insert(123, Vec::new()); // deliberately present in allow bitmap

        let prog = compile_bitmap_bpf_with_errno_syscalls(
            rules,
            &[(123, libc::ENOSYS as u32)],
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .unwrap();

        let data = make_seccomp_data(0, AUDIT_ARCH_X86_64, [0; 6]);
        assert_eq!(bpf_eval(&prog, &data), RET_ALLOW);

        let data = make_seccomp_data(123, AUDIT_ARCH_X86_64, [0; 6]);
        assert_eq!(bpf_eval(&prog, &data), RET_ERRNO_ENOSYS);

        let data = make_seccomp_data(124, AUDIT_ARCH_X86_64, [0; 6]);
        assert_eq!(bpf_eval(&prog, &data), RET_KILL);
    }

    #[test]
    fn test_wrong_arch_is_killed() {
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        rules.insert(0, Vec::new());

        let prog = compile_bitmap_bpf(
            rules,
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .unwrap();

        // Wrong architecture should return KILL_PROCESS
        let data = make_seccomp_data(0, 0xDEADBEEF, [0; 6]);
        assert_eq!(bpf_eval(&prog, &data), libc::SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn test_arg_filtered_syscalls() {
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        rules.insert(0, Vec::new()); // read: unconditional allow

        // ioctl (16): allow only TCGETS (0x5401)
        let cond =
            SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, 0x5401).unwrap();
        rules.insert(16, vec![SeccompRule::new(vec![cond]).unwrap()]);

        let prog = compile_bitmap_bpf(
            rules,
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .unwrap();

        // read: unconditional allow
        let data = make_seccomp_data(0, AUDIT_ARCH_X86_64, [0; 6]);
        assert_eq!(bpf_eval(&prog, &data), RET_ALLOW);

        // ioctl with TCGETS: allowed
        let data = make_seccomp_data(16, AUDIT_ARCH_X86_64, [0, 0x5401, 0, 0, 0, 0]);
        assert_eq!(bpf_eval(&prog, &data), RET_ALLOW);

        // ioctl with disallowed request: killed
        let data = make_seccomp_data(16, AUDIT_ARCH_X86_64, [0, 0x1234, 0, 0, 0, 0]);
        assert_eq!(bpf_eval(&prog, &data), RET_KILL);

        // unknown syscall: killed
        let data = make_seccomp_data(999, AUDIT_ARCH_X86_64, [0; 6]);
        assert_eq!(bpf_eval(&prog, &data), RET_KILL);
    }

    #[test]
    fn test_syscall_mismatch_skips_entire_arg_chain() {
        let cond = SeccompCondition::new(2, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, 0).unwrap();
        let rule = SeccompRule::new(vec![cond]).unwrap();
        let mut section = Vec::new();

        build_syscall_chain(10, vec![rule], RET_KILL, RET_ALLOW, &mut section);

        assert_eq!(section[0].code, BPF_JMP | BPF_JEQ | BPF_K);
        assert_eq!(section[0].jt, 1, "match path must skip the mismatch JA");
        assert_eq!(section[0].jf, 0, "mismatch path must take the next JA");
        assert_eq!(section[1].code, BPF_JMP | BPF_JA);

        let mismatch_target = 1 + 1 + section[1].k as usize;
        assert_eq!(
            mismatch_target,
            section.len(),
            "syscall mismatch must jump past the entire current chain"
        );
    }

    #[test]
    fn test_denied_syscall_cannot_match_mprotect_arg_predicate() {
        let rules = crate::security::SeccompManager::minimal_filter_for_test(false, &[]);
        assert!(
            !rules.contains_key(&libc::SYS_sendto),
            "sendto must be denied when networking is disabled"
        );
        assert!(
            rules
                .get(&libc::SYS_mprotect)
                .is_some_and(|chain| !chain.is_empty()),
            "mprotect must be argument-filtered in the built-in profile"
        );

        let prog = compile_bitmap_bpf(
            rules,
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .unwrap();

        for mprotect_allowed_prot in [0, libc::PROT_WRITE as u64, libc::PROT_EXEC as u64] {
            let data = make_seccomp_data(
                libc::SYS_sendto as u32,
                AUDIT_ARCH_X86_64,
                [0, 0, mprotect_allowed_prot, 0, 0, 0],
            );
            assert_eq!(
                bpf_eval(&prog, &data),
                RET_KILL,
                "denied sendto syscall must not reuse mprotect arg2 predicate ({})",
                mprotect_allowed_prot
            );
        }
    }

    #[test]
    fn test_builtin_clone3_returns_enosys() {
        let rules = crate::security::SeccompManager::minimal_filter_for_test(true, &[]);
        assert!(
            !rules.contains_key(&libc::SYS_clone3),
            "clone3 must not be in the unconditional allow bitmap"
        );

        let prog = compile_bitmap_bpf_with_errno_syscalls(
            rules,
            crate::security::SeccompManager::errno_denied_syscalls_for_test(),
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .unwrap();

        let data = make_seccomp_data(libc::SYS_clone3 as u32, AUDIT_ARCH_X86_64, [0; 6]);
        assert_eq!(bpf_eval(&prog, &data), RET_ERRNO_ENOSYS);
    }

    #[test]
    fn test_builtin_prctl_cap_ambient_only_allows_is_set() {
        let rules = crate::security::SeccompManager::minimal_filter_for_test(true, &[]);
        assert!(
            rules
                .get(&libc::SYS_prctl)
                .is_some_and(|chain| !chain.is_empty()),
            "prctl must be argument-filtered in the built-in profile"
        );

        let prog = compile_bitmap_bpf_with_errno_syscalls(
            rules,
            crate::security::SeccompManager::errno_denied_syscalls_for_test(),
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .unwrap();

        const CAP_NET_BIND_SERVICE: u64 = 10;
        let ambient_probe = make_seccomp_data(
            libc::SYS_prctl as u32,
            AUDIT_ARCH_X86_64,
            [
                libc::PR_CAP_AMBIENT as u64,
                libc::PR_CAP_AMBIENT_IS_SET as u64,
                CAP_NET_BIND_SERVICE,
                0,
                0,
                0,
            ],
        );
        assert_eq!(bpf_eval(&prog, &ambient_probe), RET_ALLOW);

        for subcommand in [
            libc::PR_CAP_AMBIENT_RAISE,
            libc::PR_CAP_AMBIENT_LOWER,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
        ] {
            let data = make_seccomp_data(
                libc::SYS_prctl as u32,
                AUDIT_ARCH_X86_64,
                [
                    libc::PR_CAP_AMBIENT as u64,
                    subcommand as u64,
                    CAP_NET_BIND_SERVICE,
                    0,
                    0,
                    0,
                ],
            );
            assert_eq!(
                bpf_eval(&prog, &data),
                RET_KILL,
                "PR_CAP_AMBIENT subcommand {} must be denied",
                subcommand
            );
        }
    }

    #[test]
    fn test_builtin_prctl_allows_pr_set_mm_for_kernel_capability_check() {
        let rules = crate::security::SeccompManager::minimal_filter_for_test(true, &[]);
        let prog = compile_bitmap_bpf_with_errno_syscalls(
            rules,
            crate::security::SeccompManager::errno_denied_syscalls_for_test(),
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .unwrap();

        let set_mm_arg_start = make_seccomp_data(
            libc::SYS_prctl as u32,
            AUDIT_ARCH_X86_64,
            [
                libc::PR_SET_MM as u64,
                libc::PR_SET_MM_ARG_START as u64,
                0x1000,
                0,
                0,
                0,
            ],
        );
        assert_eq!(bpf_eval(&prog, &set_mm_arg_start), RET_ALLOW);
    }

    #[test]
    fn test_builtin_ioctl_allows_tcgets2_for_shell_terminal_probe() {
        let rules = crate::security::SeccompManager::minimal_filter_for_test(true, &[]);
        let prog = compile_bitmap_bpf_with_errno_syscalls(
            rules,
            crate::security::SeccompManager::errno_denied_syscalls_for_test(),
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .unwrap();

        let termios2_query = make_seccomp_data(
            libc::SYS_ioctl as u32,
            AUDIT_ARCH_X86_64,
            [0, libc::TCGETS2, 0, 0, 0, 0],
        );
        assert_eq!(bpf_eval(&prog, &termios2_query), RET_ALLOW);

        let unknown_ioctl = make_seccomp_data(
            libc::SYS_ioctl as u32,
            AUDIT_ARCH_X86_64,
            [0, 0x1234, 0, 0, 0, 0],
        );
        assert_eq!(bpf_eval(&prog, &unknown_ioctl), RET_KILL);
    }

    #[test]
    fn test_preadv2_pwritev2_deny_nonzero_flags() {
        let rules = crate::security::SeccompManager::minimal_filter_for_test(true, &[]);
        for syscall in [libc::SYS_preadv2, libc::SYS_pwritev2] {
            assert!(
                rules.get(&syscall).is_some_and(|chain| !chain.is_empty()),
                "v2 vectored I/O syscalls must use argument filters"
            );
        }

        let prog = compile_bitmap_bpf_with_errno_syscalls(
            rules,
            crate::security::SeccompManager::errno_denied_syscalls_for_test(),
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .unwrap();

        const RWF_NOWAIT: u64 = 0x0000_0008;
        const RWF_HIPRI: u64 = 0x0000_0001;

        for syscall in [libc::SYS_preadv2, libc::SYS_pwritev2] {
            let data = make_seccomp_data(syscall as u32, AUDIT_ARCH_X86_64, [0; 6]);
            assert_eq!(bpf_eval(&prog, &data), RET_ALLOW);

            for flags in [RWF_NOWAIT, RWF_HIPRI, 1u64 << 32, u64::MAX] {
                let data =
                    make_seccomp_data(syscall as u32, AUDIT_ARCH_X86_64, [0, 0, 0, 0, 0, flags]);
                assert_eq!(
                    bpf_eval(&prog, &data),
                    RET_KILL,
                    "syscall {} with flags 0x{:x} must be denied",
                    syscall,
                    flags
                );
            }
        }
    }

    #[test]
    fn test_multiple_rules_per_syscall() {
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

        // socket (41): allow AF_UNIX (1) and AF_INET (2)
        let cond_unix =
            SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, 1).unwrap();
        let cond_inet =
            SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, 2).unwrap();
        rules.insert(
            41,
            vec![
                SeccompRule::new(vec![cond_unix]).unwrap(),
                SeccompRule::new(vec![cond_inet]).unwrap(),
            ],
        );

        let prog = compile_bitmap_bpf(
            rules,
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .unwrap();

        // AF_UNIX: allowed
        let data = make_seccomp_data(41, AUDIT_ARCH_X86_64, [1, 0, 0, 0, 0, 0]);
        assert_eq!(bpf_eval(&prog, &data), RET_ALLOW);

        // AF_INET: allowed
        let data = make_seccomp_data(41, AUDIT_ARCH_X86_64, [2, 0, 0, 0, 0, 0]);
        assert_eq!(bpf_eval(&prog, &data), RET_ALLOW);

        // AF_NETLINK: killed
        let data = make_seccomp_data(41, AUDIT_ARCH_X86_64, [16, 0, 0, 0, 0, 0]);
        assert_eq!(bpf_eval(&prog, &data), RET_KILL);
    }

    #[test]
    fn test_equivalence_with_linear_scan() {
        // Build the full minimal filter rules and verify bitmap BPF produces
        // the same result as seccompiler's linear-scan BPF for many syscalls.
        use seccompiler::SeccompFilter;

        let rules = crate::security::SeccompManager::minimal_filter_for_test(true, &[]);
        let rules2 = rules.clone();

        // Linear-scan BPF (seccompiler)
        let linear_prog: BpfProgram = SeccompFilter::new(
            rules,
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .unwrap()
        .try_into()
        .unwrap();

        // Bitmap BPF (ours)
        let bitmap_prog = compile_bitmap_bpf(
            rules2,
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .unwrap();

        // Test a wide range of syscall numbers with default args
        for nr in 0..500u32 {
            let data = make_seccomp_data(nr, AUDIT_ARCH_X86_64, [0; 6]);
            let linear_result = bpf_eval(&linear_prog, &data);
            let bitmap_result = bpf_eval(&bitmap_prog, &data);
            assert_eq!(
                linear_result, bitmap_result,
                "syscall {} (args=[0;6]): linear=0x{:08x}, bitmap=0x{:08x}",
                nr, linear_result, bitmap_result
            );
        }

        // Test arg-filtered syscalls with specific argument values
        // clone: namespace flags should be denied
        let clone_nr = libc::SYS_clone as u32;
        let data = make_seccomp_data(clone_nr, AUDIT_ARCH_X86_64, [0, 0, 0, 0, 0, 0]); // no ns flags
        assert_eq!(bpf_eval(&linear_prog, &data), bpf_eval(&bitmap_prog, &data));

        // ioctl: TCGETS should be allowed
        let ioctl_nr = libc::SYS_ioctl as u32;
        for req in [0x5401u64, 0x5413, 0x1234] {
            let data = make_seccomp_data(ioctl_nr, AUDIT_ARCH_X86_64, [0, req, 0, 0, 0, 0]);
            assert_eq!(
                bpf_eval(&linear_prog, &data),
                bpf_eval(&bitmap_prog, &data),
                "ioctl with req=0x{:x}",
                req
            );
        }

        // socket: AF_UNIX=1 allowed, AF_NETLINK=16 denied
        let socket_nr = libc::SYS_socket as u32;
        for domain in [1u64, 2, 10, 16] {
            let data = make_seccomp_data(socket_nr, AUDIT_ARCH_X86_64, [domain, 0, 0, 0, 0, 0]);
            assert_eq!(
                bpf_eval(&linear_prog, &data),
                bpf_eval(&bitmap_prog, &data),
                "socket with domain={}",
                domain
            );
        }
    }

    #[test]
    fn test_program_size_is_compact() {
        let rules = crate::security::SeccompManager::minimal_filter_for_test(true, &[]);
        let prog = compile_bitmap_bpf(
            rules,
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .unwrap();

        // Linear scan produces ~1119 instructions. Bitmap: ~246 (78% reduction).
        // The remaining instructions are mostly arg-check chains for ~7 syscalls.
        assert!(
            prog.len() < 400,
            "BPF program should be compact, got {} instructions",
            prog.len()
        );
        assert!(
            prog.len() < BPF_MAX_LEN,
            "BPF program must fit in {} instructions",
            BPF_MAX_LEN
        );
    }

    #[test]
    fn test_empty_rules() {
        let rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        let prog = compile_bitmap_bpf(
            rules,
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .unwrap();

        // All syscalls should be killed
        let data = make_seccomp_data(0, AUDIT_ARCH_X86_64, [0; 6]);
        assert_eq!(bpf_eval(&prog, &data), RET_KILL);
    }

    #[test]
    fn test_high_syscall_numbers() {
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        rules.insert(450, Vec::new()); // high number, still within bitmap range

        let prog = compile_bitmap_bpf(
            rules,
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .unwrap();

        let data = make_seccomp_data(450, AUDIT_ARCH_X86_64, [0; 6]);
        assert_eq!(bpf_eval(&prog, &data), RET_ALLOW);

        let data = make_seccomp_data(451, AUDIT_ARCH_X86_64, [0; 6]);
        assert_eq!(bpf_eval(&prog, &data), RET_KILL);
    }

    #[test]
    fn test_all_jump_offsets_valid() {
        let rules = crate::security::SeccompManager::minimal_filter_for_test(true, &[]);
        let prog = compile_bitmap_bpf(
            rules,
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .unwrap();

        for (pc, insn) in prog.iter().enumerate() {
            match insn.code {
                0x05 => {
                    // BPF_JMP | BPF_JA
                    let target = pc + 1 + insn.k as usize;
                    assert!(
                        target < prog.len(),
                        "JA at pc={} jumps to {} (prog len={})",
                        pc,
                        target,
                        prog.len()
                    );
                }
                0x15 | 0x25 | 0x35 => {
                    // Conditional jumps
                    let target_t = pc + 1 + insn.jt as usize;
                    let target_f = pc + 1 + insn.jf as usize;
                    assert!(
                        target_t < prog.len(),
                        "JEQ/JGT/JGE jt at pc={} jumps to {} (prog len={})",
                        pc,
                        target_t,
                        prog.len()
                    );
                    assert!(
                        target_f < prog.len(),
                        "JEQ/JGT/JGE jf at pc={} jumps to {} (prog len={})",
                        pc,
                        target_f,
                        prog.len()
                    );
                }
                _ => {}
            }
        }
    }
}
