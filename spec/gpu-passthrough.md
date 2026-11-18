# GPU Passthrough Mode

## Goal

Expose one or more host GPUs to a Nucleus container so agent workloads can run
CUDA, ROCm, Vulkan, and oneAPI/Mesa compute stacks — while preserving Nucleus's
defense-in-depth model (namespaces, cgroups, seccomp, Landlock, capabilities).

## Threat model and invariants

GPU passthrough is an **explicit privilege grant**: it hands a workload direct
access to a physical device capable of DMA, so it must be opt-in and audited.

Non-negotiable invariants preserved by this design:

1. **Opt-in only.** No device, mount, env var, or syscall relaxation happens
   unless `gpu` is configured. Default behavior is unchanged.
2. **Minimal surface.** Only the *requested* device nodes (discovered or
   explicit) and the narrow set of driver support files they require are
   exposed. No wildcard `/dev` passthrough.
3. **Defense in depth is not removed.** Namespaces, capabilities, Landlock,
   and cgroup limits all remain in force. The seccomp filter is *relaxed only
   for the syscall surface GPU drivers genuinely need* (`ioctl`), not
   disabled.
4. **Auditable.** The granted vendor, device count, and relaxed seccomp flag
   appear in the `container_started` event stream and the audit log.
5. **Production-safe.** `--gpu` is rejected in `production` service mode
   unless explicitly allowed, because production workloads must declare their
   device needs through an attested rootfs, not host device binds. (See
   "Production mode" below.)

## What GPU access requires on Linux

A container process needs all of the following to use a GPU:

| Concern | Mechanism |
|---|---|
| Device node | `/dev/nvidia0`, `/dev/dri/renderD128`, `/dev/kfd`, … recreated in the container `/dev` with the host device numbers and workload ownership. |
| Device cgroup allow | cgroup v2 has no `devices` controller file; access is gated by a `BPF_PROG_TYPE_CGROUP_DEVICE` eBPF program attached to the cgroup. |
| `ioctl` syscall | GPU drivers issue dozens of vendor-specific `ioctl` request codes (DRM, NVOS/NV_ESC_RM, KFD). Nucleus's default seccomp allowlist permits only terminal ioctls — **must be relaxed**. |
| Driver userspace | CUDA, ROCm or Mesa libraries and vendor manifests. An explicit rootfs supplies its own userspace drivers. |
| Env vars | `NVIDIA_VISIBLE_DEVICES`, `NVIDIA_DRIVER_CAPABILITIES`, etc. |

## Vendor model

```rust
enum GpuVendor { Auto, Nvidia, Amd, Intel, All }
```

`Auto` (default for `--gpu`) scans the host and selects whatever is present.
Each vendor maps to a discovery function that returns a set of host device
nodes plus the driver support paths to bind.

| Vendor | Device nodes | Support files |
|---|---|---|
| NVIDIA | `/dev/nvidia[0-9]+`, `/dev/nvidiactl`, `/dev/nvidia-uvm`, `/dev/nvidia-uvm-tools`, `/dev/nvidia-caps/*` | Individual NVIDIA libraries and vendor ICD/EGL JSON |
| AMD (ROCm) | `/dev/kfd`, `/dev/dri/renderD[0-9]+` | ROCm `/opt/amdgpu` dirs if present |
| Intel / Mesa | `/dev/dri/renderD[0-9]+` | Drivers supplied by the runtime filesystem |
| All | union of the above | union |

`renderD*` nodes are shared between AMD and Intel; `All`/`Auto` bind them and
let the workload pick the stack via its ICD config.

## Configuration

New `ContainerConfig` field:

```rust
pub gpu: Option<GpuPassthroughConfig>
```

```rust
struct GpuPassthroughConfig {
    vendor: GpuVendor,
    /// Explicit device node override. If empty, devices are discovered.
    devices: Vec<PathBuf>,
    /// NVIDIA_DRIVER_CAPABILITIES. Default "compute,utility".
    driver_capabilities: String,
    /// NVIDIA_VISIBLE_DEVICES. Default "all" for the bound set.
    visible_devices: String,
    /// Attempt to bind host driver userspace libs (NVIDIA toolkit / ROCm).
    /// Default true. Set false when the rootfs ships its own stack.
    bind_driver_libraries: bool,
}
```

Serializes to/from the launch config document (`--config`/`--config-fd`) under
`gpu`, using the same kebab-case enum spellings as the rest of the schema.

CLI surface:

```
--gpu <auto|nvidia|amd|intel|all>
--gpu-device <path>            # repeatable; overrides discovery
--gpu-driver-capabilities <s>  # default "compute,utility"
--gpu-visible-devices <s>      # default "all"
--no-gpu-driver-libs           # do not bind host driver userspace
```

## Execution flow (native)

1. **Parent, before fork:** resolve the GPU device set
   (`resolve_gpu_devices`) while still unprivileged so missing-device errors
   surface early. Build the cgroup device allowlist spec (base devices + GPU
   nodes).
2. **Cgroup setup:** after `Cgroup::create` + `set_limits`, call
   `Cgroup::install_gpu_device_allowlist`. This loads a
   `BPF_PROG_TYPE_CGROUP_DEVICE` program and attaches it to the container
   cgroup before the workload starts. If the cgroup or filter is unavailable,
   GPU setup fails unless the caller explicitly sets `--allow-degraded-security`.
3. **Child, after `create_dev_nodes`:** `mount_gpu_passthrough` creates
   independent character device nodes in the container `/dev`, preserving the
   host path and device numbers. It assigns the workload UID/GID and mode
   `0660` to these new inodes so non-root workloads can open them without
   changing host ownership or permissions, then bind-mounts support files.
   Device creation or ownership failures abort setup; native GPU setup requires
   permission to create device nodes. Existing target inodes are never reused.
4. **Seccomp:** built-in filter is built with `gpu_mode = true`, which replaces
   the default restriction for driver requests. Legacy tty requests (`0x54xx`) retain the regular terminal allowlist on every fd, and legacy console keyboard (`0x4Bxx`) and virtual terminal (`0x56xx`) requests are denied. Native custom profiles that allow `ioctl` retain the default argument checks.
5. **Landlock:** each selected GPU character node receives read, write and
   device-ioctl permissions.

## Execution flow (gVisor)

runsc implements GPU passthrough via OCI `linux.devices` plus bind mounts of
the driver files (the documented runsc GPU path; runsc additionally supports
its NVIDIA nvfs socket, but the OCI device entries are the portable path).

1. For each resolved device, emit an `OciDevice` entry (`type`, `major`,
   `minor`, `path`, `fileMode`, `uid`, `gid`). runsc creates the device node
   and installs the matching cgroup device rule inside its sandbox.
2. Bind-mount driver support files (individual NVIDIA libraries,
   ICD JSON) as OCI `bind` mounts.
3. Inject NVIDIA env vars into the process env.

runsc applies its own seccomp to the *sandbox* process; the workload ioctl
surface is handled by the sentry, so no Nucleus-side ioctl relaxation is
needed for the gVisor path.

## cgroup device allowlist (BPF)

`BPF_PROG_TYPE_CGROUP_DEVICE` programs receive a `bpf_cgroup_dev_ctx` with
three 32-bit fields. The low 16 bits of `access_type` hold the device kind
(1 for block, 2 for character). The high 16 bits hold the requested access
(mknod, read, write). The following fields hold the major and minor numbers.

The program grants all three operations for an exact match on kind, major and
minor. It denies every other device. The allowlist includes null, zero, full,
random, urandom, tty when requested, and the selected GPUs.

## Production mode

`--gpu` is rejected for `ServiceMode::Production`. Production services must
declare GPU needs through an attested rootfs and explicit, audited device
grants (future: image manifest device claims). This keeps the production
fail-closed contract intact. `agent` and `strict-agent` modes allow `--gpu`.

## Test plan

- `GpuVendor` discovery against a fake `/dev` tree (tempdir) — NVIDIA, AMD,
  Intel, none, mixed.
- Device-set resolution with explicit overrides and validation (reject
  non-device paths, reject escapes).
- Kernel loading, attachment and enforcement of the cgroup device eBPF program.
- `GpuPassthroughConfig` serde round-trip (kebab-case) and CLI mapping.
- Validation: production rejection, gvisor-host + gpu interactions, missing
  device errors.
- Native device wiring: nodes land under container `/dev` preserving host paths
  and device numbers; workload ownership permits non-root access while host
  inode ownership and permissions remain unchanged.
- gVisor wiring: `OciDevice` entries + support mounts emitted into the OCI
  config.
