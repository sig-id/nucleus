#!/usr/bin/env bash
# PostgreSQL 18 Benchmark: default I/O vs io_uring,
#   baremetal vs Nucleus (native) vs Nucleus (gVisor)
#
# Usage: sudo pg18-bench [--scale=N] [--clients=N] [--duration=N] [--skip-init]
#   or:   ROOTLESS=1 pg18-bench [...]   # unprivileged (needs /etc/subuid + cgroup v2)
#
# Requires: root (for Nucleus container operations and kernel tuning),
#           unless ROOTLESS=1 is set.
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCALE="${SCALE:-50}"            # pgbench scale factor (50 ~ 800 MB dataset)
CLIENTS="${CLIENTS:-8}"         # concurrent pgbench clients
DURATION="${DURATION:-60}"      # seconds per pgbench run
RUNS="${RUNS:-3}"               # repeat each benchmark N times
RESULTS_DIR="${RESULTS_DIR:-./results/$(date +%Y%m%d_%H%M%S)}"
SKIP_INIT="${SKIP_INIT:-0}"
GVISOR_PLATFORM="${GVISOR_PLATFORM:-kvm}"   # runsc backend: kvm (fastest, needs /dev/kvm), systrap, or ptrace
SKIP_GVISOR="${SKIP_GVISOR:-0}"             # set to 1 to skip the gVisor variant

for arg in "$@"; do
  case "$arg" in
    --scale=*)    SCALE="${arg#*=}" ;;
    --clients=*)  CLIENTS="${arg#*=}" ;;
    --duration=*) DURATION="${arg#*=}" ;;
    --runs=*)     RUNS="${arg#*=}" ;;
    --skip-init)  SKIP_INIT=1 ;;
    --help|-h)
      echo "Usage: pg18-bench [--scale=N] [--clients=N] [--duration=N] [--runs=N] [--skip-init]"
      echo "  Env vars: SCALE= CLIENTS= DURATION= RUNS= RESULTS_DIR="
      echo "            GVISOR_PLATFORM=kvm|systrap|ptrace   SKIP_GVISOR=1"
      echo "            ROOTLESS=1            # run unprivileged (Nucleus --userns keep-id)"
      echo "            USERNS_MODE=keep-id   # userns strategy under ROOTLESS=1"
      exit 0
      ;;
    *) echo "Unknown arg: $arg"; exit 1 ;;
  esac
done

mkdir -p "$RESULTS_DIR"

echo "=== PG18 I/O Benchmark ==="
echo "  scale=$SCALE  clients=$CLIENTS  duration=${DURATION}s  runs=$RUNS"
echo "  gvisor: platform=$GVISOR_PLATFORM skip=${SKIP_GVISOR}"
echo "  results -> $RESULTS_DIR"
echo ""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
PG_PORT_BARE=5480
PG_PORT_NUCLEUS=5481
PG_PORT_GVISOR=5482    # gVisor variant: hostinet, same 127.0.0.1 harness

# PostgreSQL refuses to run as root. Under ROOTLESS=1 the invoking user IS
# the PostgreSQL user (its files map to itself via --userns keep-id), so no
# privilege drop is needed. Otherwise (sudo path) drop to SUDO_USER.
if [ "$ROOTLESS" = "1" ]; then
  PG_USER="$(id -un)"
else
  PG_USER="${SUDO_USER:-nobody}"
fi
PG_UID="$(id -u "$PG_USER")"
PG_GID="$(id -g "$PG_USER")"

as_pg() {
  # Run a command as the unprivileged PG_USER. Under ROOTLESS=1 we are already
  # that user, so no privilege drop is needed.
  if [ "$ROOTLESS" = "1" ]; then
    "$@"
  else
    sudo -u "$PG_USER" --preserve-env=PATH "$@"
  fi
}

cleanup_pg() {
  local pgdata="$1"
  local port="$2"
  if [ -f "$pgdata/postmaster.pid" ]; then
    as_pg pg_ctl -D "$pgdata" -m immediate stop 2>/dev/null || true
    sleep 1
  fi
  fuser -k "${port}/tcp" 2>/dev/null || true
}

init_pgdata() {
  local pgdata="$1"

  rm -rf "$pgdata"
  mkdir -p "$pgdata"
  chown "$PG_USER" "$pgdata"
  as_pg initdb -D "$pgdata" --no-locale --encoding=UTF8 -A trust
}

write_pg_conf() {
  local pgdata="$1"
  local port="$2"
  local io_method="$3"    # "worker" or "io_uring"

  cat > "$pgdata/postgresql.conf" <<PGEOF
# --- Benchmark tuning ---
listen_addresses = '127.0.0.1'
port = $port
unix_socket_directories = '/tmp'
max_connections = 100

# Memory
shared_buffers = '256MB'
work_mem = '16MB'
maintenance_work_mem = '128MB'
effective_cache_size = '512MB'

# WAL
wal_level = minimal
max_wal_senders = 0
fsync = on
synchronous_commit = on
wal_buffers = '16MB'
checkpoint_completion_target = 0.9
max_wal_size = '1GB'

# I/O method (PG18+)
io_method = '$io_method'

# Logging (minimal for benchmarks)
logging_collector = off
log_min_messages = warning

# Misc
jit = off
PGEOF

  cat > "$pgdata/pg_hba.conf" <<HBAEOF
local   all   all                 trust
host    all   all   127.0.0.1/32  trust
HBAEOF

  chown "$PG_USER" "$pgdata/postgresql.conf" "$pgdata/pg_hba.conf"
}

start_pg() {
  local pgdata="$1"
  local port="$2"

  if ! as_pg pg_ctl -D "$pgdata" -l "$pgdata/server.log" -w -t 10 start; then
    echo "ERROR: pg_ctl start failed" >&2
    echo "--- server.log ---" >&2
    cat "$pgdata/server.log" >&2
    return 1
  fi

  for _ in $(seq 1 30); do
    if as_pg pg_isready -h 127.0.0.1 -p "$port" -q 2>/dev/null; then
      return 0
    fi
    sleep 0.3
  done
  echo "ERROR: PostgreSQL failed to start (port $port)" >&2
  echo "--- server.log ---" >&2
  cat "$pgdata/server.log" >&2
  return 1
}

stop_pg() {
  local pgdata="$1"
  as_pg pg_ctl -D "$pgdata" -m fast stop 2>/dev/null || true
}

run_pgbench_init() {
  local port="$1"

  as_pg createdb -h 127.0.0.1 -p "$port" pgbench 2>/dev/null || true
  as_pg pgbench -h 127.0.0.1 -p "$port" -i -s "$SCALE" pgbench
}

run_pgbench() {
  local port="$1"
  local mode="$2"      # "tpcb" or "select"
  local outfile="$3"

  local proto_flag=""
  case "$mode" in
    tpcb)   proto_flag="" ;;
    select) proto_flag="-S" ;;
  esac

  echo "  -> pgbench $mode (${DURATION}s, ${CLIENTS} clients) ..."

  as_pg pgbench -h 127.0.0.1 -p "$port" \
    -c "$CLIENTS" -j "$CLIENTS" \
    -T "$DURATION" \
    $proto_flag \
    --progress=10 \
    pgbench 2>&1 | tee "$outfile"
}

extract_tps() {
  grep -oP 'tps = \K[0-9.]+(?= \(without)' "$1" || echo "0"
}

extract_latency() {
  grep -oP 'latency average = \K[0-9.]+' "$1" || echo "0"
}

# ---------------------------------------------------------------------------
# Check prerequisites
# ---------------------------------------------------------------------------
# ROOTLESS=1 runs the whole benchmark as an unprivileged user (Nucleus rootless
# with --userns keep-id). Requires /etc/subuid + /etc/subgid + cgroup v2
# delegation, exactly like Docker/Podman rootless. Default (ROOTLESS unset)
# keeps the historic sudo path.
ROOTLESS="${ROOTLESS:-0}"

if [ "$ROOTLESS" != "1" ]; then
  if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: must run as root (set ROOTLESS=1 for the unprivileged path)" >&2
    exit 1
  fi
  if [ -z "${SUDO_USER:-}" ] || [ "$SUDO_USER" = "root" ]; then
    echo "ERROR: run via 'sudo pg18-bench', not as a root login" >&2
    echo "       (SUDO_USER is needed to drop privileges for PostgreSQL)" >&2
    exit 1
  fi
fi

if ! grep -q io_uring /proc/kallsyms 2>/dev/null; then
  echo "WARNING: io_uring may not be available in this kernel" >&2
fi

echo "--- System info ---"
uname -a
echo "CPUs: $(nproc)"
echo "Memory: $(free -h | awk '/^Mem:/{print $2}')"
echo ""

# ---------------------------------------------------------------------------
# Build test matrix
# ---------------------------------------------------------------------------
# gVisor is included in ENVS for the summary tables; it only ever has worker
# data (its Sentry does not implement io_uring), and the summary code skips
# any (env,io_method,workload) cell that produced no result files.
declare -a ENVS=("baremetal" "nucleus" "gvisor")
declare -a IO_MODES=("worker" "io_uring")
declare -a WORKLOADS=("tpcb" "select")

TMPBASE="$(mktemp -d /tmp/pg18bench.XXXXXX)"
chown "$PG_USER" "$TMPBASE"
trap 'cleanup_pg "$TMPBASE/pgdata_bare_worker" "$PG_PORT_BARE" 2>/dev/null; cleanup_pg "$TMPBASE/pgdata_bare_io_uring" "$PG_PORT_BARE" 2>/dev/null; cleanup_pg "$TMPBASE/pgdata_nucleus_worker" "$PG_PORT_NUCLEUS" 2>/dev/null; cleanup_pg "$TMPBASE/pgdata_nucleus_io_uring" "$PG_PORT_NUCLEUS" 2>/dev/null; cleanup_pg "$TMPBASE/pgdata_gvisor_worker" "$PG_PORT_GVISOR" 2>/dev/null; { [ -n "${NUCLEUS_BIN:-}" ] && "$NUCLEUS_BIN" delete pg18-bench-gvisor 2>/dev/null; } || true; [ "${RUNSC_SYMLINKED:-}" = "1" ] && rm -f /usr/local/bin/runsc; rm -rf "$TMPBASE"' EXIT

PG_BIN="$(dirname "$(command -v initdb)")"
# gVisor OCI mode auto-mounts host /nix/store read-only (with_host_runtime_binds)
# but NOT /run/current-system, so resolve the PG binaries to their real
# /nix/store paths — otherwise the symlinked /run/current-system/sw/bin/postgres
# is invisible inside the gVisor sandbox.
GVISOR_PG_BIN="$(dirname "$(readlink -f "$PG_BIN/postgres")")"
NUCLEUS_BIN="${NUCLEUS_BIN:-$(command -v nucleus)}"
# Rootless Nucleus selects --userns keep-id so the workload uid equals the
# invoking user and host-owned pgdata is accessible without privilege.
USERNS_FLAG=""
if [ "$ROOTLESS" = "1" ]; then
  USERNS_FLAG="--userns ${USERNS_MODE:-keep-id}"
fi

# Nucleus running as root only looks for runsc in trusted system paths.
# Symlink the Nix-provided runsc into /usr/local/bin so Nucleus can find it.
# (Rootless mode resolves runsc via PATH, so skip the symlink there.)
if [ "$ROOTLESS" != "1" ]; then
  RUNSC_NIX="$(command -v runsc 2>/dev/null || true)"
  if [ -n "$RUNSC_NIX" ] && [ ! -e /usr/local/bin/runsc ]; then
    mkdir -p /usr/local/bin
    ln -sf "$RUNSC_NIX" /usr/local/bin/runsc
    RUNSC_SYMLINKED=1
  fi
fi

echo "PG binary dir: $PG_BIN"
echo "PG version: $(postgres --version)"
echo "Nucleus binary: $NUCLEUS_BIN"
echo ""

# ---------------------------------------------------------------------------
# Baremetal benchmarks
# ---------------------------------------------------------------------------
run_baremetal_bench() {
  local io_method="$1"
  local pgdata="$TMPBASE/pgdata_bare_${io_method}"
  local port="$PG_PORT_BARE"

  echo ""
  echo "================================================================"
  echo "  BAREMETAL / io_method=$io_method"
  echo "================================================================"

  cleanup_pg "$pgdata" "$port"
  init_pgdata "$pgdata"
  write_pg_conf "$pgdata" "$port" "$io_method"
  start_pg "$pgdata" "$port"

  if [ "$SKIP_INIT" = "0" ]; then
    echo "  Initializing pgbench (scale=$SCALE) ..."
    run_pgbench_init "$port"
  fi

  as_pg psql -h 127.0.0.1 -p "$port" -c "CHECKPOINT;" pgbench

  for workload in "${WORKLOADS[@]}"; do
    for run in $(seq 1 "$RUNS"); do
      local outfile="$RESULTS_DIR/baremetal_${io_method}_${workload}_run${run}.txt"
      echo ""
      echo "  [baremetal/$io_method/$workload run=$run]"
      run_pgbench "$port" "$workload" "$outfile"
    done
  done

  stop_pg "$pgdata"
}

# ---------------------------------------------------------------------------
# Nucleus container benchmarks
# ---------------------------------------------------------------------------
run_nucleus_bench() {
  local io_method="$1"
  local pgdata="$TMPBASE/pgdata_nucleus_${io_method}"
  local port="$PG_PORT_NUCLEUS"

  echo ""
  echo "================================================================"
  echo "  NUCLEUS CONTAINER / io_method=$io_method"
  echo "================================================================"

  cleanup_pg "$pgdata" "$port"

  # Prepare pgdata on host, then run PG inside Nucleus with host networking.
  # The postgres process runs in an isolated namespace (cgroups, namespaces,
  # seccomp) while the data directory is bind-mounted in.
  init_pgdata "$pgdata"
  write_pg_conf "$pgdata" "$port" "$io_method"

  # `nucleus create` runs the container in the foreground, so we background it.
  # - Host network: pgbench on host connects via 127.0.0.1
  # - Bind-mount pgdata + /nix (for PG binaries) + /tmp
  # - trusted: host network is explicitly allowed for the benchmark harness
  # - native runtime: namespace/cgroup isolation without gVisor syscall emulation
  # Clean up any stale container state from a previous run
  "$NUCLEUS_BIN" delete "pg18-bench-${io_method}" 2>/dev/null || true

  # PostgreSQL 18 io_method=io_uring needs the io_uring syscalls to be
  # opt-in allowed and a larger memlock limit for ring buffers.
  local native_args=()
  if [ "$io_method" = "io_uring" ]; then
    native_args=(
      --seccomp-allow io_uring_setup
      --seccomp-allow io_uring_enter
      --seccomp-allow io_uring_register
      --memlock 8M
    )
  fi

  RUST_LOG=warn "$NUCLEUS_BIN" create \
    --name "pg18-bench-${io_method}" \
    --user "$PG_UID" \
    --group "$PG_GID" \
    $USERNS_FLAG \
    --network host \
    --allow-host-network \
    --runtime native \
    --trust-level trusted \
    --allow-chroot-fallback \
    --seccomp-log-denied \
    --pids 0 \
    --volume "$pgdata:/pgdata" \
    --volume "/tmp:/tmp" \
    "${native_args[@]}" \
    -- "$PG_BIN/postgres" -D /pgdata -p "$port" &

  NUCLEUS_PID=$!

  # Wait for PG to come up inside the container
  for _ in $(seq 1 30); do
    if as_pg pg_isready -h 127.0.0.1 -p "$port" -q 2>/dev/null; then
      break
    fi
    sleep 0.5
  done

  if ! as_pg pg_isready -h 127.0.0.1 -p "$port" -q 2>/dev/null; then
    echo "ERROR: PostgreSQL inside Nucleus failed to start (io_method=$io_method)" >&2
    cat "$pgdata/server.log" 2>/dev/null >&2 || true
    kill "$NUCLEUS_PID" 2>/dev/null || true
    return 1
  fi

  if [ "$SKIP_INIT" = "0" ]; then
    echo "  Initializing pgbench (scale=$SCALE) ..."
    run_pgbench_init "$port"
  fi

  as_pg psql -h 127.0.0.1 -p "$port" -c "CHECKPOINT;" pgbench

  for workload in "${WORKLOADS[@]}"; do
    for run in $(seq 1 "$RUNS"); do
      local outfile="$RESULTS_DIR/nucleus_${io_method}_${workload}_run${run}.txt"
      echo ""
      echo "  [nucleus/$io_method/$workload run=$run]"
      run_pgbench "$port" "$workload" "$outfile"
    done
  done

  # Graceful shutdown: tell PG to stop, then reap the nucleus process
  as_pg psql -h 127.0.0.1 -p "$port" -c \
    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid <> pg_backend_pid();" \
    pgbench 2>/dev/null || true
  as_pg pg_ctl -D "$pgdata" -m fast stop 2>/dev/null || true
  kill "$NUCLEUS_PID" 2>/dev/null || true
  wait "$NUCLEUS_PID" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Nucleus + gVisor container benchmark
#
# gVisor runs a userspace kernel (the Sentry) that does NOT implement the
# io_uring syscall family, so PG18's io_method=io_uring is unavailable here.
# This variant therefore runs io_method=worker only. Networking uses gVisor's
# hostinet (runsc --network=host), exposed via Nucleus's gvisor-host mode, so
# the host-side pgbench harness is unchanged: postgres binds 127.0.0.1:port
# inside the sandbox and the host connects to the same address.
# ---------------------------------------------------------------------------
run_gvisor_bench() {
  local io_method="worker"          # gVisor: worker only (no io_uring)
  local pgdata="$TMPBASE/pgdata_gvisor_${io_method}"
  local port="$PG_PORT_GVISOR"

  echo ""
  echo "================================================================"
  echo "  NUCLEUS+GVISOR CONTAINER / io_method=$io_method / platform=$GVISOR_PLATFORM"
  echo "================================================================"

  cleanup_pg "$pgdata" "$port"
  "$NUCLEUS_BIN" delete "pg18-bench-gvisor" 2>/dev/null || true

  init_pgdata "$pgdata"
  write_pg_conf "$pgdata" "$port" "$io_method"

  # gVisor-specific Nucleus flags:
  #  --runtime gvisor        : runsc sandbox
  #  --gvisor-platform kvm   : hardware-assisted syscall trap (fastest; needs
  #                            /dev/kvm). systrap/ptrace are portable fallbacks.
  #  --network gvisor-host   : runsc hostinet so the host can reach the sandbox's
  #                            bound ports (replaces native --network host)
  #  --trust-level untrusted : gVisor is the untrusted-workload runtime
  # seccomp/chroot-fallback are native-runtime concerns and are omitted here;
  # runsc applies its own seccomp policy to the Sentry.
  RUST_LOG=warn "$NUCLEUS_BIN" create \
    --name "pg18-bench-gvisor" \
    --user "$PG_UID" \
    --group "$PG_GID" \
    $USERNS_FLAG \
    --network gvisor-host \
    --allow-host-network \
    --runtime gvisor \
    --gvisor-platform "$GVISOR_PLATFORM" \
    --trust-level untrusted \
    --pids 0 \
    --volume "$pgdata:/pgdata" \
    --volume "/tmp:/tmp" \
    -- "$GVISOR_PG_BIN/postgres" -D /pgdata -p "$port" &

  NUCLEUS_PID=$!

  # gVisor boots a sandbox process + gofer; allow more time than native.
  for _ in $(seq 1 60); do
    if as_pg pg_isready -h 127.0.0.1 -p "$port" -q 2>/dev/null; then
      break
    fi
    sleep 0.5
  done

  if ! as_pg pg_isready -h 127.0.0.1 -p "$port" -q 2>/dev/null; then
    echo "ERROR: PostgreSQL inside gVisor failed to start" >&2
    cat "$pgdata/server.log" 2>/dev/null >&2 || true
    "$NUCLEUS_BIN" delete "pg18-bench-gvisor" 2>/dev/null || true
    kill "$NUCLEUS_PID" 2>/dev/null || true
    wait "$NUCLEUS_PID" 2>/dev/null || true
    return 1
  fi

  if [ "$SKIP_INIT" = "0" ]; then
    echo "  Initializing pgbench (scale=$SCALE) ..."
    run_pgbench_init "$port"
  fi

  as_pg psql -h 127.0.0.1 -p "$port" -c "CHECKPOINT;" pgbench

  for workload in "${WORKLOADS[@]}"; do
    for run in $(seq 1 "$RUNS"); do
      local outfile="$RESULTS_DIR/gvisor_${io_method}_${workload}_run${run}.txt"
      echo ""
      echo "  [gvisor/$io_method/$workload run=$run]"
      run_pgbench "$port" "$workload" "$outfile"
    done
  done

  # Graceful shutdown: terminate backends, then reap the gVisor sandbox.
  as_pg psql -h 127.0.0.1 -p "$port" -c \
    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid <> pg_backend_pid();" \
    pgbench 2>/dev/null || true
  as_pg pg_ctl -D "$pgdata" -m fast stop 2>/dev/null || true
  "$NUCLEUS_BIN" delete "pg18-bench-gvisor" 2>/dev/null || true
  kill "$NUCLEUS_PID" 2>/dev/null || true
  wait "$NUCLEUS_PID" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Run all benchmarks
# ---------------------------------------------------------------------------
for io_mode in "${IO_MODES[@]}"; do
  run_nucleus_bench "$io_mode"
done

# gVisor's Sentry does not implement io_uring, so the gVisor variant is
# worker-only.
if [ "$SKIP_GVISOR" != "1" ]; then
  if [ "$GVISOR_PLATFORM" = "kvm" ] && [ ! -e /dev/kvm ]; then
    echo "WARNING: GVISOR_PLATFORM=kvm but /dev/kvm missing; falling back to systrap" >&2
    GVISOR_PLATFORM=systrap
  fi
  run_gvisor_bench
else
  echo "Skipping gVisor variant (SKIP_GVISOR=1)"
fi

for io_mode in "${IO_MODES[@]}"; do
  run_baremetal_bench "$io_mode"
done

# ---------------------------------------------------------------------------
# Aggregate & compare results
# ---------------------------------------------------------------------------
echo ""
echo ""
echo "================================================================"
echo "  RESULTS SUMMARY"
echo "================================================================"
echo ""

SUMMARY_FILE="$RESULTS_DIR/summary.csv"
echo "env,io_method,workload,run,tps,latency_ms" > "$SUMMARY_FILE"

for env in "${ENVS[@]}"; do
  for io_mode in "${IO_MODES[@]}"; do
    for workload in "${WORKLOADS[@]}"; do
      for run in $(seq 1 "$RUNS"); do
        f="$RESULTS_DIR/${env}_${io_mode}_${workload}_run${run}.txt"
        if [ -f "$f" ]; then
          tps="$(extract_tps "$f")"
          lat="$(extract_latency "$f")"
          echo "$env,$io_mode,$workload,$run,$tps,$lat" >> "$SUMMARY_FILE"
        fi
      done
    done
  done
done

echo "Raw CSV: $SUMMARY_FILE"
echo ""

# Print comparison table
printf "%-12s %-10s %-8s %10s %10s %10s %12s\n" \
  "ENV" "IO_MODE" "WORKLOAD" "AVG_TPS" "MIN_TPS" "MAX_TPS" "AVG_LAT(ms)"
printf '%.0s-' {1..76}
echo ""

for env in "${ENVS[@]}"; do
  for io_mode in "${IO_MODES[@]}"; do
    for workload in "${WORKLOADS[@]}"; do
      read -r n avg_tps min_tps max_tps avg_lat <<< "$(awk -F, -v e="$env" -v m="$io_mode" -v w="$workload" '
        $1==e && $2==m && $3==w {
          n++; sum_tps+=$5; sum_lat+=$6
          if(n==1 || $5<min_tps) min_tps=$5
          if(n==1 || $5>max_tps) max_tps=$5
        }
        END {
          if(n>0) printf "%d %.1f %.1f %.1f %.3f", n, sum_tps/n, min_tps, max_tps, sum_lat/n
          else printf "0 - - - -"
        }' "$SUMMARY_FILE")"
      [ "${n:-0}" -gt 0 ] || continue   # skip cells with no data (e.g. gVisor/io_uring)
      printf "%-12s %-10s %-8s %10s %10s %10s %12s\n" \
        "$env" "$io_mode" "$workload" "$avg_tps" "$min_tps" "$max_tps" "$avg_lat"
    done
  done
done

echo ""
echo "--- Relative performance (vs baremetal/worker baseline) ---"
echo ""

for workload in "${WORKLOADS[@]}"; do
  read -r baseline_n baseline_tps <<< "$(awk -F, -v w="$workload" '
    $1=="baremetal" && $2=="worker" && $3==w { n++; s+=$5 }
    END { printf "%d %.1f", n, (n>0?s/n:0) }' "$SUMMARY_FILE")"
  [ "${baseline_n:-0}" -gt 0 ] || continue

  printf "%-8s baseline (baremetal/worker): %s TPS\n" "$workload" "$baseline_tps"

  for env in "${ENVS[@]}"; do
    for io_mode in "${IO_MODES[@]}"; do
      [ "$env" = "baremetal" ] && [ "$io_mode" = "worker" ] && continue
      read -r cur_n cur_tps <<< "$(awk -F, -v e="$env" -v m="$io_mode" -v w="$workload" '
        $1==e && $2==m && $3==w { n++; s+=$5 }
        END { printf "%d %.1f", n, (n>0?s/n:0) }' "$SUMMARY_FILE")"
      [ "${cur_n:-0}" -gt 0 ] || continue   # skip combos with no data
      pct=$(awk -v c="$cur_tps" -v b="$baseline_tps" 'BEGIN { printf "%.1f", (c/b) * 100 }')
      delta=$(awk -v c="$cur_tps" -v b="$baseline_tps" 'BEGIN { printf "%+.1f", ((c/b) - 1) * 100 }')
      printf "  %-12s %-10s -> %10s TPS  (%s%% of baseline, %s%%)\n" \
        "$env" "$io_mode" "$cur_tps" "$pct" "$delta"
    done
  done
  echo ""
done

echo ""
echo "--- Sandbox overhead (vs baremetal, same I/O mode) ---"
echo ""

for env in nucleus gvisor; do
  for io_mode in "${IO_MODES[@]}"; do
    for workload in "${WORKLOADS[@]}"; do
      read -r bare_n bare_tps <<< "$(awk -F, -v m="$io_mode" -v w="$workload" '
        $1=="baremetal" && $2==m && $3==w { n++; s+=$5 }
        END { printf "%d %.1f", n, (n>0?s/n:0) }' "$SUMMARY_FILE")"
      read -r env_n env_tps <<< "$(awk -F, -v e="$env" -v m="$io_mode" -v w="$workload" '
        $1==e && $2==m && $3==w { n++; s+=$5 }
        END { printf "%d %.1f", n, (n>0?s/n:0) }' "$SUMMARY_FILE")"
      [ "${env_n:-0}" -gt 0 ] || continue   # skip combos the sandbox env never ran (e.g. gVisor/io_uring)
      [ "${bare_n:-0}" -gt 0 ] || continue
      overhead=$(awk -v b="$bare_tps" -v s="$env_tps" 'BEGIN { if(b>0) printf "%.2f", (1 - (s/b)) * 100; else print "n/a" }')
      printf "  %-7s %-10s %-8s: baremetal=%s  %s=%s  overhead=%s%%\n" \
        "$env" "$io_mode" "$workload" "$bare_tps" "$env" "$env_tps" "$overhead"
    done
  done
done

echo ""
echo "Full results in: $RESULTS_DIR"
echo "Done."
