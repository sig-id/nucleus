use std::{fs, path::Path};

const GVISOR_PATCH: &str = "nix/patches/gvisor-runsc-real-exe-path.patch";

fn read_gvisor_patch() -> String {
    let patch_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(GVISOR_PATCH);
    fs::read_to_string(&patch_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {}", patch_path.display(), err))
}

fn assert_patch_contains(patch: &str, needle: &str) {
    assert!(
        patch.contains(needle),
        "expected {} to contain {:?}",
        GVISOR_PATCH,
        needle
    );
}

#[test]
fn gvisor_patch_resolves_reexec_path_to_real_runsc_binary() {
    let patch = read_gvisor_patch();

    assert_patch_contains(&patch, r#"+var ExePath = resolvedExePath()"#);
    assert_patch_contains(&patch, r#"+func resolvedExePath() string {"#);
    assert_patch_contains(&patch, r#"+	exe, err := os.Executable()"#);
    assert_patch_contains(&patch, r#"+	if err != nil || !filepath.IsAbs(exe) {"#);
    assert_patch_contains(
        &patch,
        r#"+	if resolved, err := filepath.EvalSymlinks(exe); err == nil && filepath.IsAbs(resolved) {"#,
    );
    assert_patch_contains(&patch, r#"+	info, err := os.Stat(exe)"#);
    assert_patch_contains(
        &patch,
        r#"+	if err != nil || info.IsDir() || info.Mode()&0111 == 0 {"#,
    );
    assert_patch_contains(&patch, r#"+	return exe"#);
}

#[test]
fn gvisor_patch_uses_resolved_exe_path_for_rootless_namespace_reexec() {
    let patch = read_gvisor_patch();

    assert_patch_contains(
        &patch,
        r#"-	cmd := exec.Command("/proc/self/exe", os.Args[1:]...)"#,
    );
    assert_patch_contains(&patch, r#"+	cmd := exec.Command(ExePath, os.Args[1:]...)"#);
    assert!(
        !patch.contains(r#"+	cmd := exec.Command("/proc/self/exe", os.Args[1:]...)"#),
        "{} must not add a procfs re-exec path back into MaybeRunAsRoot",
        GVISOR_PATCH
    );
}

#[test]
fn gvisor_patch_preserves_proc_self_reexec_env_for_sandbox_boot() {
    let patch = read_gvisor_patch();

    assert_patch_contains(&patch, "NUCLEUS_RUNSC_REEXEC_VIA_PROC_SELF_EXE");
    assert_patch_contains(
        &patch,
        r#"+		if os.Getenv("NUCLEUS_RUNSC_REEXEC_VIA_PROC_SELF_EXE") == "1" {"#,
    );
    assert_patch_contains(
        &patch,
        r#"+			env = append(env, "NUCLEUS_RUNSC_REEXEC_VIA_PROC_SELF_EXE=1")"#,
    );
}
