#!/usr/bin/env bash
# Owlbear end-to-end demo
#
# Builds everything, loads the kernel module, starts the daemon and game,
# runs each test cheat, and shows detection events. Cleans up on exit.
#
# Must run as root on an ARM64 system with kernel headers installed.
#
# Usage: sudo ./scripts/demo.sh

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly PROJECT_DIR="${SCRIPT_DIR}/.."
readonly LOG_FILE="/tmp/owlbear-demo.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# PIDs to clean up
DAEMON_PID=""
GAME_PID=""

log()  { echo -e "${BOLD}[demo]${NC} $*"; }
pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
info() { echo -e "${CYAN}[INFO]${NC} $*"; }

cleanup() {
    log "Cleaning up..."

    if [ -n "${GAME_PID}" ] && kill -0 "${GAME_PID}" 2>/dev/null; then
        kill "${GAME_PID}" 2>/dev/null || true
        wait "${GAME_PID}" 2>/dev/null || true
    fi

    if [ -n "${DAEMON_PID}" ] && kill -0 "${DAEMON_PID}" 2>/dev/null; then
        kill "${DAEMON_PID}" 2>/dev/null || true
        wait "${DAEMON_PID}" 2>/dev/null || true
    fi

    rm -f /tmp/owlbear-game.info

    if lsmod | grep -q owlbear; then
        rmmod owlbear 2>/dev/null || true
    fi

    log "Cleanup complete."
}

trap cleanup EXIT

# -------------------------------------------------------------------------
# Preflight checks
# -------------------------------------------------------------------------

preflight() {
    log "Preflight checks..."

    if [ "$(id -u)" -ne 0 ]; then
        fail "Must run as root"
        exit 1
    fi

    if [ "$(uname -m)" != "aarch64" ]; then
        warn "Not ARM64 — kernel module and ARM64 HW checks will not work"
        warn "Userspace components will still run"
    fi

    if [ ! -f "${PROJECT_DIR}/daemon/owlbeard" ]; then
        log "Building project..."
        make -C "${PROJECT_DIR}" daemon game cheats
    fi

    pass "Preflight OK"
}

# -------------------------------------------------------------------------
# Load kernel module
# -------------------------------------------------------------------------

load_module() {
    log "Loading kernel module..."

    if lsmod | grep -q owlbear; then
        warn "Module already loaded, removing first"
        rmmod owlbear
    fi

    if [ ! -f "${PROJECT_DIR}/kernel/owlbear.ko" ]; then
        if [ "$(uname -m)" = "aarch64" ]; then
            make -C "${PROJECT_DIR}" kernel
        else
            warn "Cannot build kernel module on $(uname -m), skipping"
            return 1
        fi
    fi

    insmod "${PROJECT_DIR}/kernel/owlbear.ko"
    sleep 1

    if [ -c /dev/owlbear ]; then
        pass "Kernel module loaded, /dev/owlbear available"
        return 0
    else
        fail "Kernel module loaded but /dev/owlbear not found"
        return 1
    fi
}

# -------------------------------------------------------------------------
# Start game
# -------------------------------------------------------------------------

start_game() {
    log "Starting test game..."

    "${PROJECT_DIR}/game/owlbear-game" --no-curses > /tmp/owlbear-game.log 2>&1 &
    GAME_PID=$!
    sleep 1

    if ! kill -0 "${GAME_PID}" 2>/dev/null; then
        fail "Game failed to start"
        return 1
    fi

    # Read PID and address from the info file written by the game
    local game_info_file="/tmp/owlbear-game.info"
    if [ -f "${game_info_file}" ]; then
        read GPID GADDR < "${game_info_file}"
        export GAME_STATE_ADDR="${GADDR:-unknown}"
    else
        warn "Info file not found, falling back to log parsing"
        local state_addr
        state_addr=$(grep "state_addr=" /tmp/owlbear-game.log 2>/dev/null | \
                     sed 's/.*state_addr=\(0x[0-9a-f]*\).*/\1/' | head -1)
        export GAME_STATE_ADDR="${state_addr:-unknown}"
    fi

    pass "Game running (PID=${GAME_PID}, state=${GAME_STATE_ADDR})"
}

# -------------------------------------------------------------------------
# Start daemon
# -------------------------------------------------------------------------

start_daemon() {
    local has_module=$1

    log "Starting daemon..."

    if [ "${has_module}" = "true" ]; then
        "${PROJECT_DIR}/daemon/owlbeard" \
            --target "${GAME_PID}" \
            --log "${LOG_FILE}" \
            > /tmp/owlbear-daemon.log 2>&1 &
        DAEMON_PID=$!
    else
        warn "No kernel module — daemon will fail to open /dev/owlbear"
        warn "Skipping daemon in this demo run"
        return 0
    fi

    sleep 1

    if ! kill -0 "${DAEMON_PID}" 2>/dev/null; then
        fail "Daemon failed to start"
        cat /tmp/owlbear-daemon.log
        return 1
    fi

    pass "Daemon running (PID=${DAEMON_PID}, target=${GAME_PID})"
}

# -------------------------------------------------------------------------
# Run test cheats
# -------------------------------------------------------------------------

run_cheat() {
    local name=$1
    local bin=$2
    shift 2
    local args=("$@")

    echo ""
    info "--- Running cheat: ${name} ---"

    timeout 5 "${bin}" "${args[@]}" > /tmp/owlbear-cheat.log 2>&1 || true

    echo "  Output (first 3 lines):"
    head -3 /tmp/owlbear-cheat.log | sed 's/^/    /'

    # Check if detection events appeared in the log
    if [ -f "${LOG_FILE}" ]; then
        local new_events
        new_events=$(grep -c "${name}\|PTRACE\|PROC_MEM\|VM_READV" "${LOG_FILE}" 2>/dev/null || echo "0")
        if [ "${new_events}" -gt 0 ]; then
            pass "Detection events generated (${new_events} events)"
        else
            warn "No detection events found for ${name}"
        fi
    fi
}

run_cheats() {
    log "Running test cheats against game (PID=${GAME_PID})..."

    local cheats_dir="${PROJECT_DIR}/cheats"

    # Cheat 1: process_vm_readv
    if [ -f "${cheats_dir}/mem_reader.bin" ] && [ "${GAME_STATE_ADDR}" != "unknown" ]; then
        run_cheat "mem_reader" "${cheats_dir}/mem_reader.bin" \
            "${GAME_PID}" "${GAME_STATE_ADDR}"
    fi

    # Cheat 2: /proc/pid/mem
    if [ -f "${cheats_dir}/proc_mem_reader.bin" ] && [ "${GAME_STATE_ADDR}" != "unknown" ]; then
        run_cheat "proc_mem_reader" "${cheats_dir}/proc_mem_reader.bin" \
            "${GAME_PID}" "${GAME_STATE_ADDR}"
    fi

    # Cheat 3: ptrace PEEKDATA
    if [ -f "${cheats_dir}/ptrace_injector.bin" ]; then
        run_cheat "ptrace_injector" "${cheats_dir}/ptrace_injector.bin"
    fi

    # Cheat 4: debug register setter
    if [ -f "${cheats_dir}/debug_reg_setter.bin" ] && [ "${GAME_STATE_ADDR}" != "unknown" ]; then
        run_cheat "debug_reg_setter" "${cheats_dir}/debug_reg_setter.bin" \
            "${GAME_PID}" "${GAME_STATE_ADDR}"
    fi
}

# -------------------------------------------------------------------------
# Show results
# -------------------------------------------------------------------------

show_results() {
    echo ""
    log "=== Detection Event Log ==="

    if [ -f "${LOG_FILE}" ]; then
        local count
        count=$(wc -l < "${LOG_FILE}")
        info "${count} events captured"
        echo ""
        # Show last 20 events
        tail -20 "${LOG_FILE}" | sed 's/^/  /'
    else
        warn "No log file found"
    fi

    echo ""

    if [ "$(uname -m)" = "aarch64" ]; then
        log "=== Kernel Module Stats ==="
        dmesg | grep owlbear | tail -10 | sed 's/^/  /'
    fi
}

# -------------------------------------------------------------------------
# Main
# -------------------------------------------------------------------------

main() {
    echo ""
    echo -e "${BOLD}================================================${NC}"
    echo -e "${BOLD}  Owlbear Anti-Cheat — End-to-End Demo${NC}"
    echo -e "${BOLD}================================================${NC}"
    echo ""

    preflight

    local has_module="false"
    if [ "$(uname -m)" = "aarch64" ]; then
        if load_module; then
            has_module="true"
        fi
    else
        warn "Skipping kernel module (not ARM64)"
    fi

    start_game
    start_daemon "${has_module}"

    sleep 2  # Let daemon settle

    run_cheats

    sleep 2  # Let events propagate

    show_results

    echo ""
    pass "Demo complete."
}

main "$@"
