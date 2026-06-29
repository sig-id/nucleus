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
| Device node | `/dev/nvidia0`, `/dev/dri/renderD128`, `/dev/kfd`, … bind-mounted into the container `/dev`. |
| Device cgroup allow | cgroup v2 has no `devices` controller file; access is gated by a `BPF_PROG_TYPE_CGROUP_DEVICE` classic-BPF program attached to the cgroup. Without one, the default is allow-all (today's Nucleus behavior). |
| `ioctl` syscall | GPU drivers issue dozens of vendor-specific `ioctl` request codes (DRM, NVOS/NV_ESC_RM, KFD). Nucleus's default seccomp allowlist permits only terminal ioctls — **must be relaxed**. |
| Driver userspace | The CUDA/ROCm/Mesa userspace libraries, Vulkan/ICD JSON, and `/proc/driver/nvidia`. Either shipped in the rootfs or bind-mounted from the host. |
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
| NVIDIA | `/dev/nvidia[0-9]+`, `/dev/nvidiactl`, `/dev/nvidia-uvm`, `/dev/nvidia-uvm-tools`, `/dev/nvidia-caps/*` | `/proc/driver/nvidia`, host driver lib dirs, ICD/EGL JSON |
| AMD (ROCm) | `/dev/kfd`, `/dev/dri/renderD[0-9]+` | ROCm `/opt/amdgpu` dirs if present |
| Intel / Mesa | `/dev/dri/renderD[0-9]+`, `/dev/dri/card[0-9]+` | Mesa ICD JSON |
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
   (`GpuDeviceSet::resolve`) while still unprivileged so missing-device errors
   surface early. Build the cgroup device allowlist spec (base devices + GPU
   nodes).
2. **Cgroup setup:** after `Cgroup::create` + `set_limits`, call
   `Cgroup::install_device_allowlist(spec)`. This loads a
   `BPF_PROG_TYPE_CGROUP_DEVICE` program and attaches it to the container
   cgroup. On kernels without `CAP_BPF`/bpf() it degrades to a warning
   (matching `--allow-degraded-security` semantics) because the *file-system*
   layer (only the bound device nodes exist in `/dev`) still gates access.
3. **Child, after `create_dev_nodes`:** `mount_gpu_passthrough` bind-mounts
   each host device node into the container `/dev` (preserving the host path
   so libraries that hardcode `/dev/nvidia0` work), bind-mounts support
   files, and chowns device nodes to the workload identity so a non-root
   workload can open them.
4. **Seccomp:** built-in filter is built with `gpu_mode = true`, which replaces
   the restrictive terminal-only `ioctl` rule with an unconditional allow.
   Custom `--seccomp-profile` users own their ioctl policy.
5. **Landlock:** the bound `/dev/*` GPU nodes and support dirs are added as
   read/write paths so Landlock does not block the workload from opening them.

## Execution flow (gVisor)

runsc implements GPU passthrough via OCI `linux.devices` plus bind mounts of
the driver files (the documented runsc GPU path; runsc additionally supports
its NVIDIA nvfs socket, but the OCI device entries are the portable path).

1. For each resolved device, emit an `OciDevice` entry (`type`, `major`,
   `minor`, `path`, `fileMode`, `uid`, `gid`). runsc creates the device node
   and installs the matching cgroup device rule inside its sandbox.
2. Bind-mount driver support files (NVIDIA `/proc/driver/nvidia`, lib dirs,
   ICD JSON) as OCI `bind` mounts.
3. Inject NVIDIA env vars into the process env.

runsc applies its own seccomp to the *sandbox* process; the workload ioctl
surface is handled by the sentry, so no Nucleus-side ioctl relaxation is
needed for the gVisor path.

## cgroup device allowlist (BPF)

`BPF_PROG_TYPE_CGROUP_DEVICE` accepts classic BPF (cBPF). The context is:

```c
struct bpf_cgroup_dev_ctx { __u32 access; __u32 type; __u32 major; __u32 minor; };
```

`access` is `DEV_READ|DEV_WRITE|DEV_MKNOD`; `type` is 1 (char) or 2 (block).

The generated program is deny-by-default with one allow block per device:

```
load type  -> if != expected, jump to next block
load major -> if != expected, jump to next block   (0xffffffff = any)
load minor -> if != expected, jump to next block   (0xffffffff = any)
load access-> and with allowed mask -> if 0, jump to next block
return ALLOW
...
return DENY
```

Base devices (null/zero/full/random/urandom/tty) are always allowed so the
existing `/dev` nodes keep working. The program is loaded with `bpf(2)` and
attached with `BPF_PROG_ATTACH` to the cgroup fd. Failure is non-fatal when
`allow_degraded_security` is set; the filesystem layer remains the primary
gate. The cBPF bytecode is pure and unit-tested without root.

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
- cgroup device cBPF bytecode generation: deterministic instruction stream,
  deny-by-default, correct major/minor/mask encoding.
- `GpuPassthroughConfig` serde round-trip (kebab-case) and CLI mapping.
- Validation: production rejection, gvisor-host + gpu interactions, missing
  device errors.
- Native mount wiring: bind targets land under container `/dev` preserving
  host paths; chown to workload identity.
- gVisor wiring: `OciDevice` entries + support mounts emitted into the OCI
  config.
