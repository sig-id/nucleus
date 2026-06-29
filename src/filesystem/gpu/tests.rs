use super::*;
use crate::container::{GpuPassthroughConfig, GpuVendor};
use std::fs;
use std::path::Path;

/// Always-true validator so tests can scan a tempdir of regular files.
fn any_exists(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok()
}

fn touch(root: &Path, rel: &str) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&path, b"x").unwrap();
}

#[test]
fn major_minor_round_trip_matches_makedev() {
    for (maj, min) in [(1u64, 3u64), (5, 0), (195, 1), (226, 0), (510, 255), (0, 0)] {
        let rdev = nix::sys::stat::makedev(maj, min);
        assert_eq!(major_of(rdev), maj as u32, "major for ({},{})", maj, min);
        assert_eq!(minor_of(rdev), min as u32, "minor for ({},{})", maj, min);
    }
}

#[test]
fn nvidia_discovery_binds_card_and_control_nodes() {
    let dir = tempfile::tempdir().unwrap();
    let dev = dir.path();
    touch(dev, "nvidia0");
    touch(dev, "nvidia1");
    touch(dev, "nvidiactl");
    touch(dev, "nvidia-uvm");
    touch(dev, "nvidia-caps/nvidia-cap1");
    // noise: must be ignored
    touch(dev, "nvidiafoo");
    touch(dev, "nvidia");

    let set = discover_gpu_with(dev, GpuVendor::Nvidia, any_exists)
        .unwrap()
        .expect("nvidia devices expected");
    assert!(set.nvidia);
    let names: Vec<String> = set
        .nodes
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
        .collect();
    assert!(names.contains(&"nvidia0".to_string()));
    assert!(names.contains(&"nvidia1".to_string()));
    assert!(names.contains(&"nvidiactl".to_string()));
    assert!(names.contains(&"nvidia-uvm".to_string()));
    assert!(names.iter().any(|n| n == "nvidia-cap1"));
    assert!(!names.contains(&"nvidiafoo".to_string()));
    assert!(!names.contains(&"nvidia".to_string()));
    // sorted
    let mut sorted = set.nodes.clone();
    sorted.sort();
    assert_eq!(set.nodes, sorted);
}

#[test]
fn amd_binds_kfd_and_render_nodes() {
    let dir = tempfile::tempdir().unwrap();
    let dev = dir.path();
    touch(dev, "kfd");
    touch(dev, "dri/renderD128");
    touch(dev, "dri/renderD129");
    touch(dev, "dri/controlD64"); // noise

    let set = discover_gpu_with(dev, GpuVendor::Amd, any_exists)
        .unwrap()
        .expect("amd devices expected");
    assert!(set.amd);
    assert!(!set.intel);
    let names: Vec<String> = set
        .nodes
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
        .collect();
    assert!(names.contains(&"kfd".to_string()));
    assert!(names.contains(&"renderD128".to_string()));
    assert!(names.contains(&"renderD129".to_string()));
    assert!(!names.contains(&"controlD64".to_string()));
}

#[test]
fn intel_binds_render_and_card_nodes() {
    let dir = tempfile::tempdir().unwrap();
    let dev = dir.path();
    touch(dev, "dri/renderD128");
    touch(dev, "dri/card0");

    let set = discover_gpu_with(dev, GpuVendor::Intel, any_exists)
        .unwrap()
        .expect("intel devices expected");
    assert!(set.intel);
    assert!(!set.amd);
    let names: Vec<String> = set
        .nodes
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
        .collect();
    assert!(names.contains(&"renderD128".to_string()));
    assert!(names.contains(&"card0".to_string()));
}

#[test]
fn render_nodes_dedup_across_amd_and_intel() {
    let dir = tempfile::tempdir().unwrap();
    let dev = dir.path();
    touch(dev, "kfd");
    touch(dev, "dri/renderD128");

    let set = discover_gpu_with(dev, GpuVendor::All, any_exists)
        .unwrap()
        .expect("devices expected");
    // renderD128 collected once for AMD and once for Intel -> must dedup to 1.
    let render_count = set
        .nodes
        .iter()
        .filter(|p| p.file_name().unwrap().to_string_lossy() == "renderD128")
        .count();
    assert_eq!(render_count, 1);
    assert!(set.amd && set.intel);
}

#[test]
fn no_devices_yields_none() {
    let dir = tempfile::tempdir().unwrap();
    touch(dir.path(), "null");
    touch(dir.path(), "random");
    let set = discover_gpu_with(dir.path(), GpuVendor::Auto, any_exists).unwrap();
    assert!(set.is_none());
}

#[test]
fn explicit_devices_resolve_and_classify() {
    // build_explicit_set is the device-validation-free core: test dedup + sort + classify.
    let nvidia0 = PathBuf::from("/dev/nvidia0");
    let kfd = PathBuf::from("/dev/kfd");
    let render = PathBuf::from("/dev/dri/renderD128");
    let set = build_explicit_set(
        &[nvidia0.clone(), nvidia0.clone(), kfd.clone(), render.clone()],
        GpuVendor::Auto,
    )
    .expect("explicit device set");
    // duplicate nvidia0 collapsed
    assert_eq!(set.len(), 3);
    assert!(set.nvidia);
    assert!(set.amd); // kfd + render classify as amd
    assert!(set.intel); // render also classifies as intel
    // sorted
    let mut sorted = set.nodes.clone();
    sorted.sort();
    assert_eq!(set.nodes, sorted);
}

#[test]
fn build_explicit_set_empty_is_none() {
    assert!(build_explicit_set(&[], GpuVendor::Auto).is_none());
}

#[test]
fn explicit_non_device_path_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("not-a-device");
    fs::write(&file, b"x").unwrap();
    let cfg = GpuPassthroughConfig {
        devices: vec![file],
        ..GpuPassthroughConfig::default()
    };
    let err = resolve_gpu_devices(&cfg).unwrap_err();
    assert!(matches!(err, NucleusError::ConfigError(_)));
}

#[test]
fn config_serde_round_trip_kebab_case() {
    let json = r#"{
        "vendor": "nvidia",
        "devices": [],
        "driver_capabilities": "compute,utility",
        "visible_devices": "all",
        "bind_driver_libraries": true
    }"#;
    let cfg: GpuPassthroughConfig = serde_json::from_str(json).unwrap();
    assert_eq!(cfg.vendor, GpuVendor::Nvidia);
    assert_eq!(cfg.driver_capabilities, "compute,utility");
    // re-serialize and check kebab-case vendor value
    let back = serde_json::to_string(&cfg).unwrap();
    assert!(back.contains("\"vendor\":\"nvidia\""));
}

#[test]
fn vendor_includes_predicates() {
    assert!(GpuVendor::Auto.includes_nvidia());
    assert!(GpuVendor::Auto.includes_amd());
    assert!(GpuVendor::Auto.includes_intel());
    assert!(GpuVendor::All.includes_nvidia());
    assert!(!GpuVendor::Nvidia.includes_amd());
    assert!(!GpuVendor::Amd.includes_nvidia());
    assert!(!GpuVendor::Intel.includes_amd());
}
