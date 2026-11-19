//! Bitmap-based BPF compiler for seccomp filters.
//!
//! Replaces seccompiler's default linear-scan BPF generation with a bitmap
//! lookup that resolves unconditional syscall allows in O(1) – a constant
//! ~10 BPF instructions regardless of allowlist size.
//!
//! Program structure:
//!
//! 1. Arch validation (3 insns)
//! 2. Argument-tested errno denies, e.g. `ENOSYS` for `clone3` or `EPERM`
//!    for namespace flags (variable)
//! 3. Compute bit_position = nr & 31 → M\[0\], word_index = nr >> 5 (5 insns)
//! 4. Dispatch on word_index → load 32-bit allow bitmap constant (≤46 insns)
//! 5. Bitmap test: `(bitmap >> bit_position) & 1` → ALLOW if set (5 insns)
//! 6. Errno bitmap dispatch + test: whole-syscall ENOSYS denies, consulted
//!    only after the allow bitmap misses (≤52 insns)
//! 7. Arg-filtered syscall chains for conditional rules (variable)
//! 8. Default deny
//!
//! Hot path for unconditional allows: ~15 instructions (vs ~120+ for linear scan).
//! Whole-syscall ENOSYS denials — the fallback for opt-in syscalls that were
//! not requested through `--seccomp-allow` (#45) — are a second bitmap so the
//! deny path stays O(1) as that set grows.

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
const BPF_JSET: u16 = 0x40;
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

/// How an errno rule tests the low 32 bits of a syscall argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ArgMatch {
    /// The argument equals the value (an int option or request code).
    Eq(u32),
    /// The argument has at least one bit of the mask set (a flag word).
    AnyBit(u32),
}

/// An errno denial may cover a whole syscall or a single int-valued option.
#[derive(Clone, Copy)]
pub(super) struct ErrnoRule {
    pub nr: i64,
    /// Test the low 32 bits of seccomp_data.args[0] (first argument, e.g. a
    /// `prctl` option or `clone` flags).
    pub arg0: Option<ArgMatch>,
    /// Test the low 32 bits of seccomp_data.args[1] (second argument, e.g. an
    /// `ioctl` request code).
    pub arg1: Option<ArgMatch>,
    /// Additional argument tests, ANDed with the fixed fields above. Several
    /// tests may target the same index: a W^X request has both the
    /// PROT_WRITE and the PROT_EXEC bit of its protection mask set, which is
    /// two `AnyBit` tests on argument 2.
    pub extra_args: &'static [(u8, ArgMatch)],
    pub errno: i32,
}

/// Compile a seccomp BPF program with exact-match syscall errno overrides.
///
/// `errno_syscalls` are split into two encodings:
///
/// - Rules that test syscall arguments run first, before the allow bitmap
///   and the argument-filtered chains. This lets the policy return `ENOSYS`
///   for syscalls such as clone3, where libc can safely fall back to an
///   older syscall the filter can inspect, or a targeted errno for a single
///   denied argument combination.
/// - Unconditional whole-syscall `ENOSYS` rules are compiled into a second
///   bitmap consulted after the allow bitmap misses and before the
///   argument-filtered chains, so a large opt-in deny set cannot regress
///   the O(1) dispatch. A syscall that is both unconditionally allowed and
///   unconditionally denied with `ENOSYS` is a contradictory policy and is
///   rejected at compile time. (Argument-tested errno rules still run
///   before everything and can override an allow for a matching argument
///   combination.)
pub(super) fn compile_bitmap_bpf_with_errno_syscalls(
    rules: BTreeMap<i64, Vec<SeccompRule>>,
    errno_syscalls: &[ErrnoRule],
    mismatch_action: SeccompAction,
    match_action: SeccompAction,
    target_arch: TargetArch,
) -> Result<BpfProgram> {
    let mismatch_val: u32 = mismatch_action.into();
    let match_val: u32 = match_action.into();
    let audit_arch = arch_audit_value(target_arch);
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

    // Whole-syscall ENOSYS denials join the second bitmap; argument-tested
    // rules and other errnos stay in the linear section. The two encodings
    // are disjoint by construction: an unconditional rule has no tests, and
    // a bitmap hit can only return ENOSYS. An unconditional ENOSYS rule for
    // a syscall that is also unconditionally allowed is a contradictory
    // policy — reject it at compile time instead of picking a winner.
    let errno_bitmap_val: u32 = SeccompAction::Errno(libc::ENOSYS as u32).into();
    let mut errno_bitmap: [u32; NUM_BITMAP_WORDS] = [0; NUM_BITMAP_WORDS];
    let mut tested_errno: Vec<&ErrnoRule> = Vec::new();
    for rule in errno_syscalls {
        let word_idx = (rule.nr >> 5) as usize;
        if rule.arg0.is_none()
            && rule.arg1.is_none()
            && rule.extra_args.is_empty()
            && rule.errno == libc::ENOSYS
            && rule.nr >= 0
            && word_idx < NUM_BITMAP_WORDS
        {
            if bitmap[word_idx] & (1u32 << (rule.nr & 31)) != 0 {
                return Err(NucleusError::SeccompError(format!(
                    "syscall {} is both unconditionally allowed and denied with ENOSYS",
                    rule.nr
                )));
            }
            errno_bitmap[word_idx] |= 1u32 << (rule.nr & 31);
        } else {
            tested_errno.push(rule);
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

    // The errno bitmap repeats the dispatch + test shape, prefixed by a
    // 2-insn reload of word_index (the allow bitmap test clobbered A and X).
    let errno_words: Vec<(usize, u32)> = errno_bitmap
        .iter()
        .enumerate()
        .filter(|(_, &w)| w != 0)
        .map(|(i, &w)| (i, w))
        .collect();
    let errno_block_len = 2 + errno_words.len() * 3 + 1;

    let mut prog: BpfProgram = Vec::with_capacity(64 + arg_section.len());

    // === Section 1: Architecture validation ===
    prog.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET));
    prog.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, audit_arch, 1, 0));
    prog.push(bpf_stmt(BPF_RET | BPF_K, libc::SECCOMP_RET_KILL_PROCESS));

    // === Section 1b: Argument-tested errno denies ===
    for rule in tested_errno {
        prog.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));
        let tests: Vec<(u32, ArgMatch)> = [(0, rule.arg0), (1, rule.arg1)]
            .into_iter()
            .filter_map(|(index, test)| test.map(|test| (index, test)))
            .chain(
                rule.extra_args
                    .iter()
                    .map(|(index, test)| (u32::from(*index), *test)),
            )
            .collect();
        // Each argument test is a load and a jump; a failed test skips the
        // remaining tests and the RET.
        let skip = 2 * tests.len() as u8 + 1;
        prog.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, rule.nr as u32, 0, skip));
        // All supported targets use little-endian seccomp_data arguments;
        // load the low 32 bits of the matched argument slot.
        let args_offset = std::mem::offset_of!(libc::seccomp_data, args) as u32;
        for (position, (index, test)) in tests.iter().enumerate() {
            let fail_skip = 2 * (tests.len() - position - 1) as u8 + 1;
            prog.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, args_offset + index * 8));
            let (op, value) = match *test {
                ArgMatch::Eq(value) => (BPF_JEQ, value),
                ArgMatch::AnyBit(mask) => (BPF_JSET, mask),
            };
            prog.push(bpf_jump(BPF_JMP | op | BPF_K, value, 0, fail_skip));
        }
        prog.push(bpf_stmt(
            BPF_RET | BPF_K,
            SeccompAction::Errno(rule.errno as u32).into(),
        ));
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
    //   JA                    →  word_index not in bitmap; skip the test
    //                          section to the errno bitmap section (or the
    //                          arg section when no errno bitmap words exist)

    let test_start = dispatch_len; // offset from dispatch start to test section
    for (entry_idx, &(word_idx, word_val)) in active_words.iter().enumerate() {
        let insn_pos = entry_idx * 3; // position within dispatch block
        prog.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, word_idx as u32, 0, 2));
        prog.push(bpf_stmt(BPF_LD | BPF_IMM, word_val));
        let ja_offset = test_start - insn_pos - 3; // distance from JA to test start
        prog.push(bpf_stmt(BPF_JMP | BPF_JA, ja_offset as u32));
    }
    // Out-of-range: jump past the test section to the errno bitmap section
    // (or straight to the arg section / default deny when it is empty).
    prog.push(bpf_stmt(BPF_JMP | BPF_JA, test_len as u32));

    // === Section 4: Bitmap test ===
    //
    // X = M[0] (bit_position)
    // A = bitmap_word >> X
    // A = A & 1
    // if A == 1: return ALLOW
    // else: fall through to the errno bitmap section
    prog.push(bpf_stmt(BPF_LDX | BPF_MEM, M_BIT_POS));
    prog.push(bpf_stmt(BPF_ALU | BPF_RSH | BPF_X, 0));
    prog.push(bpf_stmt(BPF_ALU | BPF_AND | BPF_K, 1));
    prog.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 1)); // bit set → RET
    prog.push(bpf_stmt(BPF_RET | BPF_K, match_val)); // ALLOW

    // === Section 5: Errno bitmap dispatch + test ===
    //
    // Same shape as the allow dispatch, after reloading word_index (the
    // allow bitmap test clobbered A and X; M[0] still holds bit_position).
    // A hit returns ENOSYS; a miss falls through to the arg section.
    prog.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET)); // A = nr
    prog.push(bpf_stmt(BPF_ALU | BPF_RSH | BPF_K, 5)); // A = word_index
    let errno_test_start = errno_block_len; // relative to this section start
    for (entry_idx, &(word_idx, word_val)) in errno_words.iter().enumerate() {
        let insn_pos = 2 + entry_idx * 3; // position within this section
        prog.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, word_idx as u32, 0, 2));
        prog.push(bpf_stmt(BPF_LD | BPF_IMM, word_val));
        let ja_offset = errno_test_start - insn_pos - 3;
        prog.push(bpf_stmt(BPF_JMP | BPF_JA, ja_offset as u32));
    }
    // Not in the errno bitmap either: skip its test, continue to arg section.
    prog.push(bpf_stmt(BPF_JMP | BPF_JA, test_len as u32));
    prog.push(bpf_stmt(BPF_LDX | BPF_MEM, M_BIT_POS));
    prog.push(bpf_stmt(BPF_ALU | BPF_RSH | BPF_X, 0));
    prog.push(bpf_stmt(BPF_ALU | BPF_AND | BPF_K, 1));
    prog.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 1)); // bit set → RET
    prog.push(bpf_stmt(BPF_RET | BPF_K, errno_bitmap_val)); // ERRNO | ENOSYS

    // === Section 6: Arg-filtered syscall chains ===
    prog.extend(arg_section);

    // === Section 7: Default deny ===
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
                0x45 => {
                    // BPF_JMP | BPF_JSET | BPF_K
                    if a & insn.k != 0 {
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
    const RET_ERRNO_EPERM: u32 = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;

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
    fn test_unconditional_errno_allow_overlap_is_rejected() {
        // An unconditional ENOSYS deny is compiled into the errno bitmap,
        // which is consulted only after the allow bitmap misses. Rather than
        // silently picking a winner, a syscall that is both unconditionally
        // allowed and unconditionally denied is a contradictory policy and
        // must fail loudly at compile time.
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        rules.insert(0, Vec::new()); // read
        rules.insert(123, Vec::new()); // deliberately present in allow bitmap

        let result = compile_bitmap_bpf_with_errno_syscalls(
            rules.clone(),
            &[ErrnoRule {
                nr: 123,
                arg0: None,
                arg1: None,
                errno: libc::ENOSYS,
                extra_args: &[],
            }],
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            TargetArch::x86_64,
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("123"),
            "overlap error must name the syscall: {err}"
        );

        // Disjoint policies keep the previous semantics: the errno deny
        // applies to its syscall, everything unlisted keeps the default.
        let prog = compile_bitmap_bpf_with_errno_syscalls(
            rules,
            &[ErrnoRule {
                nr: 124,
                arg0: None,
                arg1: None,
                errno: libc::ENOSYS,
                extra_args: &[],
            }],
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .unwrap();

        let data = make_seccomp_data(0, AUDIT_ARCH_X86_64, [0; 6]);
        assert_eq!(bpf_eval(&prog, &data), RET_ALLOW);

        let data = make_seccomp_data(124, AUDIT_ARCH_X86_64, [0; 6]);
        assert_eq!(bpf_eval(&prog, &data), RET_ERRNO_ENOSYS);

        let data = make_seccomp_data(125, AUDIT_ARCH_X86_64, [0; 6]);
        assert_eq!(bpf_eval(&prog, &data), RET_KILL);
    }

    #[test]
    fn test_errno_syscall_matches_second_argument() {
        // ioctl request codes live in args[1]; errno overrides must be able
        // to match them so probes like FICLONE can fall back gracefully.
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        rules.insert(0, Vec::new()); // read

        let prog = compile_bitmap_bpf_with_errno_syscalls(
            rules,
            &[ErrnoRule {
                nr: 123,
                arg0: None,
                arg1: Some(ArgMatch::Eq(libc::FICLONE as u32)),
                errno: libc::EOPNOTSUPP,
                extra_args: &[],
            }],
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .unwrap();

        // Matching request code returns the errno.
        let data = make_seccomp_data(123, AUDIT_ARCH_X86_64, [0, libc::FICLONE, 0, 0, 0, 0]);
        assert_eq!(
            bpf_eval(&prog, &data),
            libc::SECCOMP_RET_ERRNO | libc::EOPNOTSUPP as u32
        );

        // A different request code falls through to the default action.
        let data = make_seccomp_data(123, AUDIT_ARCH_X86_64, [0, 0x5401, 0, 0, 0, 0]);
        assert_eq!(bpf_eval(&prog, &data), RET_KILL);

        // Other syscalls are unaffected.
        let data = make_seccomp_data(0, AUDIT_ARCH_X86_64, [0; 6]);
        assert_eq!(bpf_eval(&prog, &data), RET_ALLOW);
    }

    #[test]
    fn test_builtin_ioctl_ficlone_returns_eopnotsupp() {
        // coreutils cp probes FICLONE on every copy and falls back to a
        // read/write loop on EOPNOTSUPP; killing the probe terminated
        // ordinary file copies with SIGSYS.
        let rules = crate::security::SeccompManager::minimal_filter_for_test(false, &[], false);
        let prog = compile_bitmap_bpf_with_errno_syscalls(
            rules,
            crate::security::SeccompManager::errno_denied_syscalls_for_test(),
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .unwrap();

        for request in [libc::FICLONE, libc::FICLONERANGE] {
            let data = make_seccomp_data(
                libc::SYS_ioctl as u32,
                AUDIT_ARCH_X86_64,
                [0, request, 0, 0, 0, 0],
            );
            assert_eq!(
                bpf_eval(&prog, &data),
                libc::SECCOMP_RET_ERRNO | libc::EOPNOTSUPP as u32,
                "ioctl request {request:#x} must return EOPNOTSUPP"
            );
        }

        // Terminal ioctls stay allowed and unknown requests stay killed.
        let data = make_seccomp_data(
            libc::SYS_ioctl as u32,
            AUDIT_ARCH_X86_64,
            [0, 0x5401, 0, 0, 0, 0], // TCGETS
        );
        assert_eq!(bpf_eval(&prog, &data), RET_ALLOW);

        let data = make_seccomp_data(
            libc::SYS_ioctl as u32,
            AUDIT_ARCH_X86_64,
            [0, 0xdead_beef, 0, 0, 0, 0],
        );
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
        let rules = crate::security::SeccompManager::minimal_filter_for_test(false, &[], false);
        assert!(
            !rules.contains_key(&libc::SYS_bpf),
            "bpf must be denied: it is neither allowed nor on the opt-in list"
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
                libc::SYS_bpf as u32,
                AUDIT_ARCH_X86_64,
                [0, 0, mprotect_allowed_prot, 0, 0, 0],
            );
            assert_eq!(
                bpf_eval(&prog, &data),
                RET_KILL,
                "denied bpf syscall must not reuse mprotect arg2 predicate ({})",
                mprotect_allowed_prot
            );
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn custom_clone_profile_intersects_each_allow_rule_with_namespace_mask() {
        use crate::security::SeccompManager;
        let profile = tempfile::NamedTempFile::new().unwrap();
        let contents = serde_json::json!({
            "defaultAction": "SCMP_ACT_KILL_PROCESS",
            "syscalls": [
                {"names":["clone"], "action":"SCMP_ACT_ALLOW", "args":[
                    {"index":0, "op":"SCMP_CMP_MASKED_EQ", "value":libc::CLONE_THREAD, "valueTwo":libc::CLONE_THREAD},
                    {"index":1, "op":"SCMP_CMP_NE", "value":0}
                ]},
                {"names":["clone"], "action":"SCMP_ACT_ALLOW", "args":[
                    {"index":0, "op":"SCMP_CMP_EQ", "value":libc::SIGCHLD}
                ]}
            ]
        });
        std::fs::write(profile.path(), contents.to_string()).unwrap();
        let program = SeccompManager::compile_profile(profile.path(), None, false).unwrap();
        let action = |flags: i32, stack| {
            bpf_eval(
                &program,
                &make_seccomp_data(
                    libc::SYS_clone as u32,
                    AUDIT_ARCH_X86_64,
                    [flags as u64, stack, 0, 0, 0, 0],
                ),
            )
        };
        assert_eq!(action(libc::CLONE_THREAD | libc::CLONE_VM, 1), RET_ALLOW);
        assert_eq!(action(libc::SIGCHLD, 0), RET_ALLOW);
        assert_eq!(action(libc::CLONE_THREAD, 0), RET_KILL);
        assert_eq!(action(libc::CLONE_VM, 1), RET_KILL);
        // Namespace creation is refused before the profile's allow rules.
        assert_eq!(
            action(libc::CLONE_THREAD | libc::CLONE_NEWUSER, 1),
            RET_ERRNO_EPERM
        );
    }

    #[test]
    fn test_errno_rule_tests_every_argument() {
        let prog = compile_bitmap_bpf_with_errno_syscalls(
            BTreeMap::new(),
            &[ErrnoRule {
                nr: 123,
                arg0: Some(ArgMatch::AnyBit(0b1100)),
                arg1: Some(ArgMatch::Eq(7)),
                errno: libc::EPERM,
                extra_args: &[],
            }],
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .unwrap();
        let action = |arg0, arg1| {
            bpf_eval(
                &prog,
                &make_seccomp_data(123, AUDIT_ARCH_X86_64, [arg0, arg1, 0, 0, 0, 0]),
            )
        };
        assert_eq!(action(0b0100, 7), RET_ERRNO_EPERM);
        assert_eq!(action(0b1000, 7), RET_ERRNO_EPERM);
        assert_eq!(action(0b0011, 7), RET_KILL);
        assert_eq!(action(0b0100, 8), RET_KILL);
        // A failed first test must not fall into the second one with A
        // still holding args[0].
        assert_eq!(action(7, 7), RET_ERRNO_EPERM);
        assert_eq!(action(0, 0), RET_KILL);
    }

    #[test]
    fn test_builtin_namespace_creation_returns_eperm() {
        // Nested sandboxes (bwrap, unshare -U) must see EPERM, not SIGSYS.
        let rules = crate::security::SeccompManager::minimal_filter_for_test(false, &[], false);
        let prog = compile_bitmap_bpf_with_errno_syscalls(
            rules,
            crate::security::SeccompManager::errno_denied_syscalls_for_test(),
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .unwrap();
        let action = |nr: i64, arg0: i32| {
            bpf_eval(
                &prog,
                &make_seccomp_data(nr as u32, AUDIT_ARCH_X86_64, [arg0 as u64, 0, 0, 0, 0, 0]),
            )
        };
        for flag in [
            libc::CLONE_NEWUSER,
            libc::CLONE_NEWNS,
            libc::CLONE_NEWNET,
            libc::CLONE_NEWIPC,
            libc::CLONE_NEWUTS,
            libc::CLONE_NEWPID,
            libc::CLONE_NEWCGROUP,
            libc::CLONE_NEWTIME,
        ] {
            assert_eq!(
                action(libc::SYS_unshare, flag),
                RET_ERRNO_EPERM,
                "{flag:#x}"
            );
            assert_eq!(
                action(libc::SYS_clone, flag | libc::SIGCHLD),
                RET_ERRNO_EPERM,
                "{flag:#x}"
            );
        }
        assert_eq!(action(libc::SYS_setns, 0), RET_ERRNO_EPERM);
        // fork() still works; unshare of non-namespace state stays denied.
        assert_eq!(action(libc::SYS_clone, libc::SIGCHLD), RET_ALLOW);
        assert_eq!(action(libc::SYS_unshare, libc::CLONE_FILES), RET_KILL);
    }

    #[test]
    fn test_builtin_clone3_returns_enosys() {
        let rules = crate::security::SeccompManager::minimal_filter_for_test(true, &[], false);
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

    // Exercise the assembled program with --seccomp-allow requests included.
    // The requests must preserve all argument checks and network-mode gates.
    fn network_and_futex_program(network: bool) -> BpfProgram {
        let extra = ["futex", "socket", "socketpair", "setsockopt"].map(String::from);
        let rules =
            crate::security::SeccompManager::minimal_filter_for_test(network, &extra, false);
        compile_bitmap_bpf(
            rules,
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .unwrap()
    }

    fn check_int_args(prog: &BpfProgram, syscall: i64, args: [i32; 3], expected: u32) {
        // The kernel interprets each of these arguments as a 32-bit int.
        for high_bits in [0, 1u64 << 32] {
            let [a, b, c] = args.map(|arg| high_bits | arg as u32 as u64);
            let data = make_seccomp_data(syscall as u32, AUDIT_ARCH_X86_64, [a, b, c, 0, 0, 0]);
            assert_eq!(
                bpf_eval(prog, &data),
                expected,
                "syscall {syscall}, args {args:?}"
            );
        }
    }

    #[test]
    fn test_builtin_futex_operations() {
        for network in [false, true] {
            let prog = network_and_futex_program(network);
            for flags in [
                0,
                libc::FUTEX_PRIVATE_FLAG,
                libc::FUTEX_CLOCK_REALTIME,
                libc::FUTEX_PRIVATE_FLAG | libc::FUTEX_CLOCK_REALTIME,
            ] {
                for op in [
                    libc::FUTEX_WAIT,
                    libc::FUTEX_WAKE,
                    libc::FUTEX_WAIT_BITSET,
                    libc::FUTEX_WAKE_BITSET,
                    libc::FUTEX_REQUEUE,
                    libc::FUTEX_CMP_REQUEUE,
                    libc::FUTEX_WAKE_OP,
                ] {
                    check_int_args(&prog, libc::SYS_futex, [0, op | flags, 0], RET_ALLOW);
                }
                for op in [
                    libc::FUTEX_LOCK_PI,
                    libc::FUTEX_LOCK_PI2,
                    libc::FUTEX_TRYLOCK_PI,
                    libc::FUTEX_UNLOCK_PI,
                    libc::FUTEX_WAIT_REQUEUE_PI,
                    libc::FUTEX_CMP_REQUEUE_PI,
                    0x10000 | libc::FUTEX_WAIT,
                ] {
                    check_int_args(&prog, libc::SYS_futex, [0, op | flags, 0], RET_KILL);
                }
            }
        }
    }

    #[test]
    fn test_builtin_socket_protocols_and_options() {
        const IPPROTO_L2TP: i32 = 115;
        for network in [false, true] {
            let prog = network_and_futex_program(network);
            let network_action = if network { RET_ALLOW } else { RET_KILL };
            for nr in [libc::SYS_socket, libc::SYS_socketpair] {
                for kind in [libc::SOCK_STREAM, libc::SOCK_DGRAM, libc::SOCK_SEQPACKET] {
                    check_int_args(&prog, nr, [libc::AF_UNIX, kind, 0], RET_ALLOW);
                }
                check_int_args(&prog, nr, [libc::AF_NETLINK, libc::SOCK_DGRAM, 0], RET_KILL);
            }
            for domain in [libc::AF_INET, libc::AF_INET6] {
                for flags in [
                    0,
                    libc::SOCK_NONBLOCK,
                    libc::SOCK_CLOEXEC,
                    libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                ] {
                    for (kind, proto) in [
                        (libc::SOCK_STREAM, 0),
                        (libc::SOCK_STREAM, libc::IPPROTO_TCP),
                        (libc::SOCK_DGRAM, 0),
                        (libc::SOCK_DGRAM, libc::IPPROTO_UDP),
                    ] {
                        let args = [domain, kind | flags, proto];
                        check_int_args(&prog, libc::SYS_socket, args, network_action);
                        check_int_args(&prog, libc::SYS_socketpair, args, RET_KILL);
                    }
                }
                for (kind, proto) in [
                    (libc::SOCK_STREAM, libc::IPPROTO_SCTP),
                    (libc::SOCK_STREAM, libc::IPPROTO_MPTCP),
                    (libc::SOCK_DGRAM, IPPROTO_L2TP),
                    (libc::SOCK_RAW, libc::IPPROTO_TCP),
                    (libc::SOCK_SEQPACKET, 0),
                    (libc::SOCK_STREAM, libc::IPPROTO_UDP),
                    (libc::SOCK_DGRAM, libc::IPPROTO_TCP),
                    (libc::SOCK_STREAM | 0x10000, 0),
                ] {
                    check_int_args(&prog, libc::SYS_socket, [domain, kind, proto], RET_KILL);
                }
            }
            for (level, option, action) in [
                (libc::IPPROTO_TCP, libc::TCP_ULP, RET_KILL),
                (libc::IPPROTO_TCP, libc::TCP_NODELAY, network_action),
                (libc::SOL_SOCKET, libc::SO_REUSEADDR, network_action),
                (libc::SOL_SOCKET, libc::TCP_ULP, network_action),
            ] {
                check_int_args(&prog, libc::SYS_setsockopt, [0, level, option], action);
            }
        }
    }

    #[test]
    fn test_builtin_prctl_cap_ambient_only_allows_is_set() {
        let rules = crate::security::SeccompManager::minimal_filter_for_test(true, &[], false);
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
    fn hardened_mapping_transfer_and_gpu_rules_survive_compilation() {
        use crate::security::SeccompManager;
        let action = |prog: &BpfProgram, nr: i64, args: [u64; 6]| {
            bpf_eval(
                prog,
                &make_seccomp_data(
                    nr as u32,
                    arch_audit_value(std::env::consts::ARCH.try_into().unwrap()),
                    args,
                ),
            )
        };
        let extra = [
            "mmap",
            "pkey_mprotect",
            "personality",
            "splice",
            "tee",
            "sendfile",
            "pidfd_getfd",
            "mknodat",
            "kcmp",
        ]
        .map(String::from);
        let gpu = SeccompManager::compile_builtin(false, &extra, true, false).unwrap();
        let custom = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(custom.path(), r#"{"defaultAction":"SCMP_ACT_KILL_PROCESS","architectures":[],"syscalls":[{"names":["mmap","mprotect","pkey_mprotect","shmat","personality","prctl","ioctl","mknodat","kcmp"],"action":"SCMP_ACT_ALLOW"}]}"#).unwrap();
        let profile = SeccompManager::compile_profile(custom.path(), None, false).unwrap();
        for prog in [&gpu, &profile] {
            for nr in [libc::SYS_mmap, libc::SYS_mprotect, libc::SYS_pkey_mprotect] {
                for (prot, expected) in [
                    (libc::PROT_READ | libc::PROT_WRITE, RET_ALLOW),
                    (libc::PROT_READ | libc::PROT_EXEC, RET_ALLOW),
                    // Refused, but with the errno the kernel uses for the
                    // same denial, not a kill (#46).
                    (
                        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                        WX_REFUSED,
                    ),
                    (libc::PROT_WRITE | libc::PROT_EXEC, WX_REFUSED),
                ] {
                    assert_eq!(action(prog, nr, [0, 4096, prot as u64, 0, 0, 0]), expected);
                }
            }
            // A read-only executable view could alias a writable attachment.
            for (flags, expected) in [
                (0, RET_ALLOW),
                (libc::SHM_RDONLY, RET_ALLOW),
                (libc::SHM_EXEC, RET_KILL),
                (libc::SHM_EXEC | libc::SHM_RDONLY, RET_KILL),
            ] {
                assert_eq!(
                    action(prog, libc::SYS_shmat, [0, 0, flags as u64, 0, 0, 0]),
                    expected
                );
            }
            // FIFOs, sockets and regular files may be created; devices may not.
            for (kind, expected) in [
                (libc::S_IFIFO, RET_ALLOW),
                (libc::S_IFSOCK, RET_ALLOW),
                (libc::S_IFREG, RET_ALLOW),
                (0, RET_ALLOW),
                (libc::S_IFCHR, RET_KILL),
                (libc::S_IFBLK, RET_KILL),
            ] {
                assert_eq!(
                    action(
                        prog,
                        libc::SYS_mknodat,
                        [0, 0, (kind | 0o600) as u64, 0, 0, 0]
                    ),
                    expected
                );
            }
            for (kind, expected) in [(0, RET_ALLOW), (1, RET_KILL), (6, RET_KILL)] {
                assert_eq!(
                    action(prog, libc::SYS_kcmp, [1, 1, kind, 0, 0, 0]),
                    expected
                );
            }
            assert_eq!(
                action(
                    prog,
                    libc::SYS_personality,
                    [libc::READ_IMPLIES_EXEC as u64, 0, 0, 0, 0, 0]
                ),
                RET_KILL
            );
            for option in [libc::PR_SET_MM_MAP, libc::PR_SET_MM_ARG_START] {
                assert_eq!(
                    action(
                        prog,
                        libc::SYS_prctl,
                        [
                            (1 << 32) | libc::PR_SET_MM as u64,
                            option as u64,
                            0,
                            0,
                            0,
                            0
                        ]
                    ),
                    libc::SECCOMP_RET_ERRNO | libc::EPERM as u32
                );
            }
            // Terminal injection, console keyboard (KDSKBSENT, KDSETMODE) and
            // virtual terminal (VT_ACTIVATE, VT_SETMODE) requests.
            for request in [
                libc::TIOCLINUX,
                libc::TIOCSTI,
                libc::TIOCCONS,
                0x4b49,
                0x4b3a,
                0x5606,
                0x5602,
            ] {
                assert_eq!(
                    action(prog, libc::SYS_ioctl, [1, (1 << 32) | request, 0, 0, 0, 0]),
                    RET_KILL
                );
            }
        }
        // Representative DRM, AMD KFD and range-boundary requests remain
        // available to the GPU driver.
        for request in [
            0xc0406400, 0x80084b01, 0x4aff, 0x4c00, 0x53ff, 0x5500, 0x5700,
        ] {
            assert_eq!(
                action(&gpu, libc::SYS_ioctl, [3, request, 0, 0, 0, 0]),
                RET_ALLOW
            );
        }
        for network in [false, true] {
            let default = SeccompManager::compile_builtin(network, &[], false, false).unwrap();
            for nr in [
                libc::SYS_splice,
                libc::SYS_tee,
                crate::security::syscall_numbers::SYS_SENDFILE,
            ] {
                // Callers fall back to read/write when the syscall is absent.
                assert_eq!(
                    action(&default, nr, [0; 6]),
                    libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32
                );
                assert_eq!(action(&gpu, nr, [0; 6]), RET_ALLOW);
            }
            for nr in [libc::SYS_mknodat, libc::SYS_kcmp] {
                // #45: opt-in syscalls that were not requested degrade to
                // ENOSYS instead of SIGSYS; both are argument-filtered when
                // they are requested via --seccomp-allow.
                assert_eq!(
                    action(&default, nr, [0; 6]),
                    libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32
                );
                // Requested (the `gpu` program opts in) they keep their
                // argument-filtered allow: mode/type predicates apply.
                assert_eq!(action(&gpu, nr, [0; 6]), RET_ALLOW);
            }
        }
        assert_eq!(action(&gpu, libc::SYS_pidfd_getfd, [0; 6]), RET_KILL);
    }

    /// The verdict for a mapping request that is writable and executable.
    const WX_REFUSED: u32 = libc::SECCOMP_RET_ERRNO | libc::EACCES as u32;

    #[test]
    fn node_startup_probes_are_allowed_by_default() {
        // V8 and abseil name every anonymous region they map, and libuv
        // reads its own capability sets; Node 26 does both before user code
        // runs, and either one used to end in SIGSYS.
        use crate::security::SeccompManager;
        let default = SeccompManager::compile_builtin(false, &[], false, false).unwrap();
        let action = |nr: i64, args: [u64; 6]| {
            bpf_eval(
                &default,
                &make_seccomp_data(
                    nr as u32,
                    arch_audit_value(std::env::consts::ARCH.try_into().unwrap()),
                    args,
                ),
            )
        };
        // uapi: PR_SET_VMA = 0x53564d41 ("SVMA"), PR_SET_VMA_ANON_NAME = 0.
        const PR_SET_VMA: u64 = 0x5356_4d41;
        assert_eq!(
            action(
                libc::SYS_prctl,
                [PR_SET_VMA, 0, 0x1000, 4096, 0x7f00_0000_dead, 0]
            ),
            RET_ALLOW
        );
        // Only the naming subcommand is allowed.
        for subcommand in [1, 2] {
            assert_eq!(
                action(libc::SYS_prctl, [PR_SET_VMA, subcommand, 0, 0, 0, 0]),
                RET_KILL
            );
        }
        assert_eq!(action(libc::SYS_capget, [0; 6]), RET_ALLOW);
        // capset changes credentials and stays denied.
        assert_eq!(action(libc::SYS_capset, [0; 6]), RET_KILL);
    }

    #[test]
    fn jit_allowance_permits_wx_mappings_and_survives_profiles() {
        use crate::security::SeccompManager;
        let action = |prog: &BpfProgram, nr: i64, args: [u64; 6]| {
            bpf_eval(
                prog,
                &make_seccomp_data(
                    nr as u32,
                    arch_audit_value(std::env::consts::ARCH.try_into().unwrap()),
                    args,
                ),
            )
        };
        let rwx = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
        let jit = SeccompManager::compile_builtin(true, &[], false, true).unwrap();
        let strict = SeccompManager::compile_builtin(true, &[], false, false).unwrap();

        // V8 manages its code range through mprotect/pkey_mprotect and maps
        // RWX during startup; the allowance keeps those calls alive instead
        // of SIGSYS (#46).
        for nr in [libc::SYS_mmap, libc::SYS_mprotect, libc::SYS_pkey_mprotect] {
            assert_eq!(action(&jit, nr, [0, 4096, rwx as u64, 0, 0, 0]), RET_ALLOW);
        }
        for nr in [libc::SYS_mmap, libc::SYS_mprotect] {
            assert_eq!(
                action(&strict, nr, [0, 4096, rwx as u64, 0, 0, 0]),
                WX_REFUSED
            );
        }
        // Without the allowance pkey_mprotect is an un-requested opt-in
        // syscall, which reports ENOSYS whatever its arguments (#45).
        assert_eq!(
            action(
                &strict,
                libc::SYS_pkey_mprotect,
                [0, 4096, rwx as u64, 0, 0, 0]
            ),
            libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32
        );
        // The allowance grants no other memory escape hatch.
        assert_eq!(
            action(
                &jit,
                libc::SYS_shmat,
                [0, 0, libc::SHM_EXEC as u64, 0, 0, 0]
            ),
            RET_KILL
        );
        assert_eq!(action(&jit, libc::SYS_memfd_create, [0; 6]), RET_KILL);

        // The same relaxation reaches custom profiles: with the allowance a
        // listed mprotect stays unconditional, without it the built-in W^X
        // argument filters are merged in (SEC-01).
        let custom = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(custom.path(), r#"{"defaultAction":"SCMP_ACT_KILL_PROCESS","architectures":[],"syscalls":[{"names":["mmap","mprotect"],"action":"SCMP_ACT_ALLOW"}]}"#).unwrap();
        let profile_jit = SeccompManager::compile_profile(custom.path(), None, true).unwrap();
        let profile_strict = SeccompManager::compile_profile(custom.path(), None, false).unwrap();
        for nr in [libc::SYS_mmap, libc::SYS_mprotect] {
            assert_eq!(
                action(&profile_jit, nr, [0, 4096, rwx as u64, 0, 0, 0]),
                RET_ALLOW
            );
            assert_eq!(
                action(&profile_strict, nr, [0, 4096, rwx as u64, 0, 0, 0]),
                WX_REFUSED
            );
        }
    }

    #[test]
    fn setsockopt_level_allowlist_and_msg_oob_survive_compilation() {
        use crate::security::SeccompManager;
        let action = |prog: &BpfProgram, nr: i64, args: [u64; 6]| {
            bpf_eval(
                prog,
                &make_seccomp_data(
                    nr as u32,
                    arch_audit_value(std::env::consts::ARCH.try_into().unwrap()),
                    args,
                ),
            )
        };
        let network = SeccompManager::compile_builtin(true, &[], false, false).unwrap();
        let setsockopt = |level: i64, option: i64| {
            action(
                &network,
                libc::SYS_setsockopt,
                [0, level as u64, option as u64, 0, 0, 0],
            )
        };
        // Well-known socket-option levels stay available.
        for level in [
            libc::SOL_SOCKET,
            libc::IPPROTO_IP,
            libc::IPPROTO_TCP,
            libc::IPPROTO_UDP,
            libc::IPPROTO_IPV6,
        ] {
            assert_eq!(setsockopt(level as i64, 1), RET_ALLOW);
        }
        // Unknown levels reach unrelated subsystems and stay denied. ICMPv6
        // options are only reachable through raw ICMPv6 sockets, which the
        // socket() filter denies in the first place.
        for level in [
            libc::SOL_NETLINK,
            libc::SOL_ALG,
            libc::IPPROTO_RAW,
            libc::IPPROTO_UDPLITE,
            libc::SOL_XDP,
            libc::IPPROTO_ICMPV6,
        ] {
            assert_eq!(setsockopt(level as i64, 1), RET_KILL);
        }
        // Protocol-attachment options are denied even at allowed levels:
        // TCP_ULP loads upper-layer protocols and UDP_ENCAP reaches the xfrm
        // ESP-in-UDP input path.
        assert_eq!(
            setsockopt(libc::IPPROTO_TCP as i64, libc::TCP_ULP as i64),
            RET_KILL
        );
        assert_eq!(
            setsockopt(libc::IPPROTO_UDP as i64, libc::UDP_ENCAP as i64),
            RET_KILL
        );
        assert_eq!(
            setsockopt(libc::IPPROTO_TCP as i64, libc::TCP_NODELAY as i64),
            RET_ALLOW
        );

        // Out-of-band data is denied on the flags argument of every
        // send/recv entry point; ordinary flags keep working.
        for (nr, flags_arg) in [
            (libc::SYS_sendto, 3),
            (libc::SYS_recvfrom, 3),
            (libc::SYS_sendmsg, 2),
            (libc::SYS_recvmsg, 2),
        ] {
            let mut args = [0u64; 6];
            args[flags_arg] = (libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) as u64;
            assert_eq!(action(&network, nr, args), RET_ALLOW);
            args[flags_arg] = libc::MSG_OOB as u64;
            assert_eq!(action(&network, nr, args), RET_KILL);
            args[flags_arg] = (libc::MSG_OOB | libc::MSG_DONTWAIT) as u64;
            assert_eq!(action(&network, nr, args), RET_KILL);
        }

        // Without network mode setsockopt stays denied, but the send/recv
        // transfer entry points are argument-filtered in every mode: local
        // IPC is available with networking denied, so Unix datagram users
        // (Codex's signal thread) survive; only MSG_OOB stays denied (#45).
        let offline = SeccompManager::compile_builtin(false, &[], false, false).unwrap();
        assert_eq!(action(&offline, libc::SYS_setsockopt, [0; 6]), RET_KILL);
        for (nr, flags_arg) in [
            (libc::SYS_sendto, 3),
            (libc::SYS_recvfrom, 3),
            (libc::SYS_sendmsg, 2),
            (libc::SYS_recvmsg, 2),
        ] {
            let mut args = [0u64; 6];
            assert_eq!(action(&offline, nr, args), RET_ALLOW);
            args[flags_arg] = libc::MSG_OOB as u64;
            assert_eq!(action(&offline, nr, args), RET_KILL);
        }
        // Network sockets themselves still cannot be created offline.
        let mut inet = [0u64; 6];
        inet[0] = libc::AF_INET as u64;
        inet[1] = libc::SOCK_STREAM as u64;
        assert_eq!(action(&offline, libc::SYS_socket, inet), RET_KILL);
    }

    #[test]
    fn unrequested_opt_in_syscalls_degrade_to_enosys_not_sigsys() {
        // #45: an opt-in syscall that was not requested through
        // --seccomp-allow must not kill the process. ENOSYS is what a kernel
        // without the syscall returns, so probing runtimes and libc fall
        // back or report a normal error instead of dying with SIGSYS:
        // inotify watchers, extended attribute writes, pidfds (Go, tokio), protection keys (V8), libuv's io_uring probe,
        // and the splice-family transfers.
        use crate::security::SeccompManager;
        let action = |prog: &BpfProgram, nr: i64, args: [u64; 6]| {
            bpf_eval(
                prog,
                &make_seccomp_data(
                    nr as u32,
                    arch_audit_value(std::env::consts::ARCH.try_into().unwrap()),
                    args,
                ),
            )
        };
        let default = SeccompManager::compile_builtin(false, &[], false, false).unwrap();
        let enosys = libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32;
        let probes = [
            ("inotify_init1", libc::SYS_inotify_init1),
            ("setxattr", libc::SYS_setxattr),
            ("pkey_alloc", libc::SYS_pkey_alloc),
            ("timer_create", libc::SYS_timer_create),
            ("pidfd_open", libc::SYS_pidfd_open),
            ("sysinfo", libc::SYS_sysinfo),
            ("setpriority", libc::SYS_setpriority),
            ("setrlimit", libc::SYS_setrlimit),
            ("io_uring_setup", libc::SYS_io_uring_setup),
            ("io_cancel", libc::SYS_io_cancel),
            ("splice", libc::SYS_splice),
        ];
        for (name, nr) in probes {
            assert_eq!(
                action(&default, nr, [0; 6]),
                enosys,
                "{name} must degrade to ENOSYS when not opted in"
            );
        }

        // The calls ordinary tools need in order to work, not merely to
        // survive, are allowed by default: timestamps (`touch`, `tar`,
        // `cp -p`, `make`), creat, fchmodat2 and read-only queries.
        for name in [
            "utimensat",
            "creat",
            "fchmodat2",
            "getsid",
            "getpriority",
            "sched_getattr",
            "sched_get_priority_max",
        ] {
            let Some(nr) = crate::security::seccomp::syscall_number_for_test(name) else {
                continue; // not present on this architecture
            };
            assert_eq!(
                action(&default, nr, [0; 6]),
                RET_ALLOW,
                "{name} must be allowed by default"
            );
        }
        // Their mutating siblings stay opt-in.
        for nr in [libc::SYS_setpriority, libc::SYS_sched_setattr] {
            assert_eq!(action(&default, nr, [0; 6]), enosys);
        }

        // Opting in suppresses the override and yields the real syscall.
        let extra: Vec<String> = probes.iter().map(|(name, _)| name.to_string()).collect();
        let opted_in = SeccompManager::compile_builtin(false, &extra, false, false).unwrap();
        for (_, nr) in probes {
            assert_eq!(action(&opted_in, nr, [0; 6]), RET_ALLOW);
        }

        // The security boundary is untouched: security-critical, privileged
        // and non-opt-in syscalls keep the KILL_PROCESS default, and the
        // clone3 fallback still returns ENOSYS so libc falls back to the
        // filtered clone path.
        for nr in [libc::SYS_add_key, libc::SYS_ptrace, libc::SYS_bpf] {
            assert_eq!(action(&default, nr, [0; 6]), RET_KILL);
        }
        assert_eq!(action(&default, libc::SYS_clone3, [0; 6]), enosys);

        // The deny fallback stays a bitmap dispatch: the whole-syscall
        // ENOSYS set must not turn the program into a linear scan.
        assert!(
            default.len() < 700,
            "built-in BPF program should stay compact, got {} instructions",
            default.len()
        );
    }

    #[test]
    fn test_builtin_prctl_denies_pr_set_mm_before_capability_checks() {
        let rules = crate::security::SeccompManager::minimal_filter_for_test(true, &[], false);
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
        assert_eq!(
            bpf_eval(&prog, &set_mm_arg_start),
            libc::SECCOMP_RET_ERRNO | libc::EPERM as u32
        );
    }

    #[test]
    fn test_builtin_ioctl_allows_tcgets2_for_shell_terminal_probe() {
        let rules = crate::security::SeccompManager::minimal_filter_for_test(true, &[], false);
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
        let rules = crate::security::SeccompManager::minimal_filter_for_test(true, &[], false);
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

        let rules = crate::security::SeccompManager::minimal_filter_for_test(true, &[], false);
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
        let rules = crate::security::SeccompManager::minimal_filter_for_test(true, &[], false);
        let prog = compile_bitmap_bpf(
            rules,
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .unwrap();

        // Keep the network-enabled filter compact as argument predicates
        // evolve. The setsockopt level allowlist and the MSG_OOB flag filters
        // deliberately widened the linear section; the budget leaves room
        // only for small, reviewed additions.
        assert!(
            prog.len() < 520,
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
        let rules = crate::security::SeccompManager::minimal_filter_for_test(true, &[], false);
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
