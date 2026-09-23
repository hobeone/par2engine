#!/bin/bash
# run_gremlins.sh - Run gremlins mutation testing with resource limits.
#
# Guards against three failure modes observed in practice on a sibling Go
# repo (gonzbd) running the same tool:
#
#  1. Disk blowup. gremlins copies the whole working directory into each
#     worker's isolated build dir, and does not respect .gitignore while
#     doing so. If the scratch directory lives inside the repo tree, each
#     worker's copy recursively sweeps up scratch data left by prior
#     workers/runs, nesting many levels deep (observed: 168-394GB from a
#     single run, entirely self-referential). Scratch space is placed
#     OUTSIDE the repo tree below, and wiped before each run, so a worker
#     copy can never fold in previous scratch data.
#
#  2. OOM. Many parallel workers each running `go test` can exceed system
#     RAM. An unconfined run lets the *system* OOM killer pick victims,
#     which can kill unrelated processes on the machine. The run below is
#     wrapped in a systemd --user cgroup scope with a hard MemoryMax, so
#     only this run's own processes are killed on OOM.
#
#  3. Runaway/unbounded runs. A background watchdog enforces a wall-clock
#     timeout and a disk-usage cap on the scratch directory, and stops the
#     cgroup scope (killing the whole process tree) if either is exceeded.
#     This is a backstop for causes of runaway resource use other than #1.
#
# Tunables (all optional):
#   GREMLINS_DIR          scratch dir base (default: ~/.cache/par2engine-gremlins)
#   GREMLINS_WORKERS       parallel workers (default: auto based on CPU/RAM, min 4, max 16)
#   GREMLINS_MEMORY_MAX    hard memory cap for the whole run (default: 80% of system RAM, fallback 32G)
#   GREMLINS_DISK_MAX_MB   scratch-dir size cap in MiB (default: 51200 = 50GiB)
#   GREMLINS_TIMEOUT_SECS  wall-clock cap in seconds (default: 1800 = 30min)

set -uo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 ./<package> [extra gremlins args...]" >&2
    exit 1
fi

pkg="$1"
shift

REPO_ROOT="$(git rev-parse --show-toplevel)"

# Scratch space must live outside the repo tree — see failure mode #1 above.
BASE_DIR="${GREMLINS_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/par2engine-gremlins}"
case "$BASE_DIR" in
    "$REPO_ROOT"|"$REPO_ROOT"/*)
        echo "error: GREMLINS_DIR ($BASE_DIR) must not be inside the repo ($REPO_ROOT)" >&2
        exit 1
        ;;
esac

TMP_DIR="${BASE_DIR}/tmp"
export GOCACHE="${BASE_DIR}/gocache"

# Start each run from a clean scratch dir: leftover worker dirs from a prior
# (especially crashed) run are the seed for the recursive blowup in failure
# mode #1, and aren't useful to keep between runs anyway. GOCACHE is left
# alone — it's content-addressed and safe (and worth keeping) across runs.
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR" "$GOCACHE"
export TMPDIR="$TMP_DIR"

# Auto-detect default workers and memory cap based on system CPU cores and RAM
DEFAULT_WORKERS=4
DEFAULT_MEMORY_MAX="32G"

if command -v nproc >/dev/null 2>&1; then
    cpu_cores=$(nproc)
    cpu_workers=$(( cpu_cores / 2 ))
else
    cpu_workers=4
fi

if [ -r /proc/meminfo ]; then
    mem_kb=$(awk '/MemTotal:/ {print $2}' /proc/meminfo)
    mem_gb=$(( mem_kb / 1024 / 1024 ))
    if [ "$mem_gb" -gt 0 ]; then
        ram_workers=$(( mem_gb / 4 ))
        calc_mem_max_gb=$(( mem_gb * 80 / 100 ))
        if [ "$calc_mem_max_gb" -ge 1 ]; then
            DEFAULT_MEMORY_MAX="${calc_mem_max_gb}G"
        fi
    else
        ram_workers=4
    fi
else
    ram_workers=4
fi

if [ "$ram_workers" -lt "$cpu_workers" ]; then
    auto_workers="$ram_workers"
else
    auto_workers="$cpu_workers"
fi

if [ "$auto_workers" -lt 4 ]; then
    DEFAULT_WORKERS=4
elif [ "$auto_workers" -gt 16 ]; then
    DEFAULT_WORKERS=16
else
    DEFAULT_WORKERS="$auto_workers"
fi

WORKERS="${GREMLINS_WORKERS:-$DEFAULT_WORKERS}"
MEMORY_MAX="${GREMLINS_MEMORY_MAX:-$DEFAULT_MEMORY_MAX}"
DISK_MAX_MB="${GREMLINS_DISK_MAX_MB:-51200}"
TIMEOUT_SECS="${GREMLINS_TIMEOUT_SECS:-1800}"

if ! command -v systemd-run >/dev/null 2>&1; then
    echo "error: systemd-run not found - this script requires it to enforce memory/process limits" >&2
    exit 1
fi

UNIT_NAME="par2engine-gremlins-$$"

echo "Running gremlins on $pkg"
echo "  TMPDIR=$TMPDIR GOCACHE=$GOCACHE"
echo "  workers=$WORKERS memory-max=$MEMORY_MAX disk-max=${DISK_MAX_MB}MiB timeout=${TIMEOUT_SECS}s"
echo "  cgroup unit=${UNIT_NAME}.scope"

# Watchdog: stops the cgroup scope (killing the whole process tree) if the
# scratch dir outgrows DISK_MAX_MB or the run outlives TIMEOUT_SECS. gremlins
# has no built-in disk-space limit, and MemoryMax alone doesn't bound wall
# clock or disk, hence this backstop.
(
    elapsed=0
    while true; do
        sleep 15
        elapsed=$((elapsed + 15))
        used_mb=$(du -sm "$TMP_DIR" 2>/dev/null | cut -f1)
        if [ -n "$used_mb" ] && [ "$used_mb" -gt "$DISK_MAX_MB" ]; then
            echo "error: gremlins scratch dir exceeded ${DISK_MAX_MB}MiB (at ${used_mb}MiB) - stopping run" >&2
            systemctl --user stop "${UNIT_NAME}.scope" 2>/dev/null
            exit 0
        fi
        if [ "$elapsed" -ge "$TIMEOUT_SECS" ]; then
            echo "error: gremlins run exceeded ${TIMEOUT_SECS}s wall clock - stopping run" >&2
            systemctl --user stop "${UNIT_NAME}.scope" 2>/dev/null
            exit 0
        fi
        # Stop watching once the scope is gone (run finished on its own).
        systemctl --user is-active --quiet "${UNIT_NAME}.scope" 2>/dev/null || exit 0
    done
) &
watchdog_pid=$!

cleanup() {
    kill "$watchdog_pid" 2>/dev/null || true
    # gremlins exiting (e.g. after printing its summary) does not guarantee
    # every worker's `go test` child has exited too — a mutant that hit its
    # own -test.timeout can be reparented and keep running, still inside this
    # scope's cgroup, chewing CPU/RAM with nothing left to report it. Stopping
    # the scope explicitly reaps the whole process tree instead of trusting
    # systemd to notice the cgroup emptied out on its own.
    systemctl --user stop "${UNIT_NAME}.scope" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

systemd-run --user --scope --unit="$UNIT_NAME" \
    -p "MemoryMax=${MEMORY_MAX}" \
    -p "TasksMax=4096" \
    -- gremlins unleash --workers "$WORKERS" "$pkg" "$@"
status=$?

if [ "$status" -eq 137 ]; then
    echo "error: gremlins run was OOM-killed or stopped by the watchdog (memory-max=$MEMORY_MAX) - try a lower GREMLINS_WORKERS" >&2
elif [ "$status" -eq 143 ]; then
    echo "error: gremlins run was stopped by the disk/timeout watchdog - see message above for which limit" >&2
fi

exit "$status"
