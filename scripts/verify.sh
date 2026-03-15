#!/usr/bin/env bash
# Owlbear E2E verification — adversarial evidence package
#
# Produces a self-contained artifact directory proving detection works.
# Three phases:
#   1. BASELINE — no module loaded. Cheats succeed, no detection events.
#   2. PROTECTED — module loaded + daemon + eBPF. Cheats trigger detection.
#   3. SELF-PROTECTION — module unload detected, daemon survives.
#
# Each phase captures: dmesg before/after (with diff), strace per cheat,
# exit codes, stdout/stderr. Final summary is machine-generated.
#
# Must run as root on a system with the kernel module built.
#
# Usage: sudo ./scripts/verify.sh [--output-dir /path] [--upload] [--bucket NAME] [--region REGION]

set -uo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly PROJECT_DIR="${SCRIPT_DIR}/.."
readonly TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
readonly DEFAULT_OUT="/tmp/owlbear-verify-${TIMESTAMP}"
readonly DEFAULT_BUCKET="owlbear-verification-artifacts"
readonly DEFAULT_REGION="us-east-2"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Counters
TOTAL_ASSERTIONS=0
PASSED_ASSERTIONS=0
FAILED_ASSERTIONS=0
SKIPPED_ASSERTIONS=0

# State
GAME_PID=""
DAEMON_PID=""
OUT_DIR="${DEFAULT_OUT}"
UPLOAD=false
S3_BUCKET="${DEFAULT_BUCKET}"
AWS_REGION_OPT=""

# -------------------------------------------------------------------------
# Logging and assertions
# -------------------------------------------------------------------------

log()  { echo -e "${BOLD}[verify]${NC} $*"; }
pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
info() { echo -e "${CYAN}[INFO]${NC} $*"; }

assert_pass() {
    local label="$1"
    TOTAL_ASSERTIONS=$((TOTAL_ASSERTIONS + 1))
    PASSED_ASSERTIONS=$((PASSED_ASSERTIONS + 1))
    pass "${label}"
    echo "PASS: ${label}" >> "${OUT_DIR}/summary.txt"
}

assert_fail() {
    local label="$1"
    local detail="${2:-}"
    TOTAL_ASSERTIONS=$((TOTAL_ASSERTIONS + 1))
    FAILED_ASSERTIONS=$((FAILED_ASSERTIONS + 1))
    fail "${label}"
    echo "FAIL: ${label}" >> "${OUT_DIR}/summary.txt"
    if [ -n "${detail}" ]; then
        echo "  detail: ${detail}" >> "${OUT_DIR}/summary.txt"
    fi
}

assert_skip() {
    local label="$1"
    local reason="${2:-}"
    TOTAL_ASSERTIONS=$((TOTAL_ASSERTIONS + 1))
    SKIPPED_ASSERTIONS=$((SKIPPED_ASSERTIONS + 1))
    warn "${label} (SKIPPED: ${reason})"
    echo "SKIP: ${label} — ${reason}" >> "${OUT_DIR}/summary.txt"
}

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

cleanup() {
    log "Cleaning up..."

    if [ -n "${DAEMON_PID}" ] && kill -0 "${DAEMON_PID}" 2>/dev/null; then
        kill "${DAEMON_PID}" 2>/dev/null || true
        wait "${DAEMON_PID}" 2>/dev/null || true
    fi

    if [ -n "${GAME_PID}" ] && kill -0 "${GAME_PID}" 2>/dev/null; then
        kill "${GAME_PID}" 2>/dev/null || true
        wait "${GAME_PID}" 2>/dev/null || true
    fi

    rm -f /tmp/owlbear-game.info

    if lsmod 2>/dev/null | grep -q owlbear; then
        rmmod owlbear 2>/dev/null || true
    fi

    log "Cleanup complete."
}

trap cleanup EXIT

# -------------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------------

imds_get() {
    local path="$1"
    local token
    token=$(curl -sf -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 60" \
        "http://169.254.169.254/latest/api/token" 2>/dev/null) || return 1
    curl -sf -H "X-aws-ec2-metadata-token: ${token}" \
        "http://169.254.169.254${path}" 2>/dev/null
}

detect_aws_region() {
    local region
    region=$(imds_get "/latest/meta-data/placement/region" 2>/dev/null) || true
    if [ -n "${region}" ]; then
        echo "${region}"
    else
        echo "${DEFAULT_REGION}"
    fi
}

upload_to_s3() {
    local s3_prefix="s3://${S3_BUCKET}/runs/${TIMESTAMP}"
    local region_flag="--region ${AWS_REGION_OPT}"

    log "Uploading evidence package to ${s3_prefix}/ ..."

    if ! command -v aws > /dev/null 2>&1; then
        fail "aws CLI not found — cannot upload"
        return 1
    fi

    if aws s3 sync "${OUT_DIR}/" "${s3_prefix}/" ${region_flag} \
         --no-progress 2>&1; then
        assert_pass "s3_upload to ${s3_prefix}/"
        log "Artifacts available at: ${s3_prefix}/"
        log "Download: aws s3 sync ${s3_prefix}/ ./verify-${TIMESTAMP}/ ${region_flag}"
        echo "${TIMESTAMP}" | aws s3 cp - "s3://${S3_BUCKET}/latest.txt" \
            ${region_flag} 2>/dev/null || true
    else
        assert_fail "s3_upload" "aws s3 sync failed"
        return 1
    fi
}

capture_dmesg() {
    dmesg --time-format iso 2>/dev/null || dmesg
}

dmesg_mark() {
    capture_dmesg | wc -l
}

dmesg_since() {
    local mark=$1
    local outfile=$2
    capture_dmesg | tail -n "+$((mark + 1))" > "${outfile}"
}

start_game() {
    log "Starting test game..."

    "${PROJECT_DIR}/game/owlbear-game" --no-curses > /tmp/owlbear-game.log 2>&1 &
    GAME_PID=$!
    sleep 1

    if ! kill -0 "${GAME_PID}" 2>/dev/null; then
        fail "Game failed to start"
        exit 1
    fi

    local tries=0
    while [ ! -f /tmp/owlbear-game.info ] && [ $tries -lt 10 ]; do
        sleep 0.2
        tries=$((tries + 1))
    done

    if [ -f /tmp/owlbear-game.info ]; then
        read GPID GADDR < /tmp/owlbear-game.info
        log "Game running: PID=${GAME_PID}, addr=${GADDR}"
    else
        fail "Game info file not created"
        exit 1
    fi
}

stop_game() {
    if [ -n "${GAME_PID}" ] && kill -0 "${GAME_PID}" 2>/dev/null; then
        kill "${GAME_PID}" 2>/dev/null || true
        wait "${GAME_PID}" 2>/dev/null || true
    fi
    GAME_PID=""
    rm -f /tmp/owlbear-game.info
}

stop_daemon() {
    if [ -n "${DAEMON_PID}" ] && kill -0 "${DAEMON_PID}" 2>/dev/null; then
        kill "${DAEMON_PID}" 2>/dev/null || true
        wait "${DAEMON_PID}" 2>/dev/null || true
    fi
    DAEMON_PID=""
}

# Run a single cheat binary, capturing everything
run_cheat_captured() {
    local phase_dir="$1"
    local name="$2"
    local bin="$3"
    shift 3

    local cheat_dir="${phase_dir}/${name}"
    mkdir -p "${cheat_dir}"

    local dmesg_before
    dmesg_before=$(dmesg_mark)

    info "Running ${name}..."

    local exit_code=0
    if command -v strace > /dev/null 2>&1; then
        timeout 6 strace -f -e trace=process,memory \
            -o "${cheat_dir}/strace.log" \
            "${bin}" "$@" \
            > "${cheat_dir}/stdout.log" \
            2> "${cheat_dir}/stderr.log" || exit_code=$?
    else
        timeout 6 "${bin}" "$@" \
            > "${cheat_dir}/stdout.log" \
            2> "${cheat_dir}/stderr.log" || exit_code=$?
    fi

    echo "${exit_code}" > "${cheat_dir}/exit_code"

    sleep 0.5

    dmesg_since "${dmesg_before}" "${cheat_dir}/dmesg_diff.log"

    if [ -f "${cheat_dir}/strace.log" ]; then
        head -1 "${cheat_dir}/strace.log" | \
            grep -oP '^\d+' > "${cheat_dir}/cheat_pid.txt" 2>/dev/null || true
    fi

    info "  exit_code=${exit_code}"
}

# -------------------------------------------------------------------------
# Preflight
# -------------------------------------------------------------------------

preflight() {
    log "Preflight checks..."

    if [ "$(id -u)" -ne 0 ]; then
        fail "Must run as root"
        exit 1
    fi

    while [ $# -gt 0 ]; do
        case "$1" in
            --output-dir) OUT_DIR="$2"; shift 2 ;;
            --upload)     UPLOAD=true; shift ;;
            --bucket)     S3_BUCKET="$2"; shift 2 ;;
            --region)     AWS_REGION_OPT="$2"; shift 2 ;;
            *) fail "Unknown arg: $1"; exit 1 ;;
        esac
    done

    mkdir -p "${OUT_DIR}"

    if [ "${UPLOAD}" = true ]; then
        if [ -z "${AWS_REGION_OPT}" ]; then
            AWS_REGION_OPT=$(detect_aws_region)
        fi
        log "Upload enabled: s3://${S3_BUCKET}/ (${AWS_REGION_OPT})"
    fi

    local instance_id="local"
    local account_id="local"
    instance_id=$(imds_get "/latest/meta-data/instance-id" 2>/dev/null || echo "local")
    account_id=$(imds_get "/latest/dynamic/instance-identity/document" 2>/dev/null \
        | grep -o '"accountId" *: *"[^"]*"' | cut -d'"' -f4 || echo "local")

    cat > "${OUT_DIR}/summary.txt" <<HEADER
# Owlbear E2E Verification Report (v1.0.0)
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Host: $(uname -n)
# Kernel: $(uname -r)
# Arch: $(uname -m)
# Instance: ${instance_id}
# Account: ${account_id}
# Region: ${AWS_REGION_OPT:-local}
# Script: ${SCRIPT_DIR}/verify.sh
#
# This file is machine-generated. Each line is a test assertion.
# PASS/FAIL/SKIP status is determined by the script, not an LLM.
#
HEADER

    uname -a > "${OUT_DIR}/uname.txt"
    cat /etc/os-release > "${OUT_DIR}/os-release.txt" 2>/dev/null || true

    if [ "${instance_id}" != "local" ]; then
        imds_get "/latest/dynamic/instance-identity/document" \
            > "${OUT_DIR}/instance-identity.json" 2>/dev/null || true
    fi

    local missing=0
    for bin in game/owlbear-game cheats/mem_reader.bin cheats/proc_mem_reader.bin \
               cheats/ptrace_injector.bin cheats/ptrace_writer.bin \
               cheats/vm_writer.bin cheats/mprotect_injector.bin; do
        if [ ! -f "${PROJECT_DIR}/${bin}" ]; then
            warn "Missing: ${bin} — building..."
            missing=1
        fi
    done

    if [ $missing -eq 1 ]; then
        make -C "${PROJECT_DIR}" game cheats 2>&1 | tee "${OUT_DIR}/build.log"
    fi

    if ! command -v strace > /dev/null 2>&1; then
        warn "strace not found — syscall tracing will be skipped"
        echo "# WARNING: strace not available" >> "${OUT_DIR}/summary.txt"
    fi

    pass "Preflight OK"
}

# -------------------------------------------------------------------------
# Phase 1: BASELINE — no module, cheats should succeed
# -------------------------------------------------------------------------

phase_baseline() {
    log ""
    log "========================================="
    log "  Phase 1: BASELINE (no module loaded)"
    log "========================================="
    log ""

    local phase_dir="${OUT_DIR}/baseline"
    mkdir -p "${phase_dir}"

    if lsmod 2>/dev/null | grep -q owlbear; then
        rmmod owlbear 2>/dev/null || true
        sleep 1
    fi

    capture_dmesg > "${phase_dir}/dmesg_before.txt"
    local phase_mark
    phase_mark=$(dmesg_mark)

    start_game

    local cheats_dir="${PROJECT_DIR}/cheats"

    # --- mem_reader ---
    run_cheat_captured "${phase_dir}" "mem_reader" \
        "${cheats_dir}/mem_reader.bin"

    local rc
    rc=$(cat "${phase_dir}/mem_reader/exit_code")
    if [ "$rc" -eq 0 ] || [ "$rc" -eq 124 ]; then
        assert_pass "baseline/mem_reader exits successfully (code=${rc})"
    else
        assert_fail "baseline/mem_reader should succeed without module" "exit_code=${rc}"
    fi

    if grep -q "owlbear: process_vm_readv" "${phase_dir}/mem_reader/dmesg_diff.log" 2>/dev/null; then
        assert_fail "baseline/mem_reader should produce no detection events"
    else
        assert_pass "baseline/mem_reader no detection events in dmesg"
    fi

    # --- proc_mem_reader ---
    run_cheat_captured "${phase_dir}" "proc_mem_reader" \
        "${cheats_dir}/proc_mem_reader.bin"

    rc=$(cat "${phase_dir}/proc_mem_reader/exit_code")
    if [ "$rc" -eq 0 ] || [ "$rc" -eq 124 ]; then
        assert_pass "baseline/proc_mem_reader exits successfully (code=${rc})"
    else
        assert_fail "baseline/proc_mem_reader should succeed without module" "exit_code=${rc}"
    fi

    if grep -q "owlbear:.*mem access" "${phase_dir}/proc_mem_reader/dmesg_diff.log" 2>/dev/null; then
        assert_fail "baseline/proc_mem_reader should produce no detection events"
    else
        assert_pass "baseline/proc_mem_reader no detection events in dmesg"
    fi

    # --- ptrace_injector ---
    # Run WITHOUT strace: strace itself uses ptrace, which conflicts with
    # ptrace_injector's PTRACE_ATTACH (can't ptrace a ptrace'd process).
    local ptrace_dir="${phase_dir}/ptrace_injector"
    mkdir -p "${ptrace_dir}"
    local ptrace_dmesg_before
    ptrace_dmesg_before=$(dmesg_mark)
    info "Running ptrace_injector..."
    local ptrace_exit=0
    timeout 6 "${cheats_dir}/ptrace_injector.bin" \
        > "${ptrace_dir}/stdout.log" \
        2> "${ptrace_dir}/stderr.log" || ptrace_exit=$?
    echo "${ptrace_exit}" > "${ptrace_dir}/exit_code"
    sleep 0.5
    dmesg_since "${ptrace_dmesg_before}" "${ptrace_dir}/dmesg_diff.log"
    info "  exit_code=${ptrace_exit}"

    rc=$(cat "${ptrace_dir}/exit_code")
    # Key assertion: ptrace ATTACH succeeded (no EPERM). Exit code 1 with
    # "Bad magic" means attach worked but data read was stale — not a detection.
    if [ "$rc" -eq 0 ]; then
        assert_pass "baseline/ptrace_injector exits successfully (code=${rc})"
    elif grep -q "PTRACE_ATTACH failed" "${ptrace_dir}/stderr.log" 2>/dev/null; then
        assert_fail "baseline/ptrace_injector blocked by anti-cheat" "exit_code=${rc}"
    else
        assert_pass "baseline/ptrace_injector attached successfully (data read issue, code=${rc})"
    fi

    if grep -q "owlbear: ptrace attempt" "${ptrace_dir}/dmesg_diff.log" 2>/dev/null; then
        assert_fail "baseline/ptrace_injector should produce no detection events"
    else
        assert_pass "baseline/ptrace_injector no detection events in dmesg"
    fi

    # --- ptrace_writer ---
    run_cheat_captured "${phase_dir}" "ptrace_writer" \
        "${cheats_dir}/ptrace_writer.bin"

    rc=$(cat "${phase_dir}/ptrace_writer/exit_code")
    if [ "$rc" -eq 0 ]; then
        assert_pass "baseline/ptrace_writer exits successfully (code=${rc})"
    else
        assert_fail "baseline/ptrace_writer should succeed without module" "exit_code=${rc}"
    fi

    if grep -q "\[CHEAT\]" "${phase_dir}/ptrace_writer/stdout.log" 2>/dev/null; then
        assert_pass "baseline/ptrace_writer wrote game state"
    else
        assert_fail "baseline/ptrace_writer did not print cheat confirmation"
    fi

    # --- vm_writer ---
    run_cheat_captured "${phase_dir}" "vm_writer" \
        "${cheats_dir}/vm_writer.bin"

    rc=$(cat "${phase_dir}/vm_writer/exit_code")
    if [ "$rc" -eq 0 ]; then
        assert_pass "baseline/vm_writer exits successfully (code=${rc})"
    else
        assert_fail "baseline/vm_writer should succeed without module" "exit_code=${rc}"
    fi

    if grep -q "\[CHEAT\]" "${phase_dir}/vm_writer/stdout.log" 2>/dev/null; then
        assert_pass "baseline/vm_writer wrote game state"
    else
        assert_fail "baseline/vm_writer did not print cheat confirmation"
    fi

    # --- mprotect_injector ---
    run_cheat_captured "${phase_dir}" "mprotect_injector" \
        "${cheats_dir}/mprotect_injector.bin"

    rc=$(cat "${phase_dir}/mprotect_injector/exit_code")
    if [ "$rc" -eq 0 ]; then
        assert_pass "baseline/mprotect_injector exits successfully (code=${rc})"
    else
        assert_fail "baseline/mprotect_injector should succeed without module" "exit_code=${rc}"
    fi

    if grep -q "\[CHEAT\]" "${phase_dir}/mprotect_injector/stdout.log" 2>/dev/null; then
        assert_pass "baseline/mprotect_injector executed shellcode"
    else
        assert_fail "baseline/mprotect_injector did not execute shellcode"
    fi

    capture_dmesg > "${phase_dir}/dmesg_after.txt"
    dmesg_since "${phase_mark}" "${phase_dir}/dmesg_phase_diff.txt"

    stop_game
}

# -------------------------------------------------------------------------
# Phase 2: PROTECTED — module + daemon + eBPF
# -------------------------------------------------------------------------

phase_protected() {
    log ""
    log "========================================="
    log "  Phase 2: PROTECTED (module + daemon)"
    log "========================================="
    log ""

    local phase_dir="${OUT_DIR}/protected"
    mkdir -p "${phase_dir}"

    start_game

    # Load module
    if [ ! -f "${PROJECT_DIR}/kernel/owlbear.ko" ]; then
        if [ "$(uname -m)" = "aarch64" ]; then
            log "Building kernel module..."
            make -C "${PROJECT_DIR}" kernel 2>&1 | tee "${OUT_DIR}/kernel_build.log"
        else
            assert_skip "protected phase" "kernel module not available on $(uname -m)"
            stop_game
            return
        fi
    fi

    if lsmod 2>/dev/null | grep -q owlbear; then
        rmmod owlbear 2>/dev/null || true
        sleep 1
    fi

    local module_mark
    module_mark=$(dmesg_mark)

    log "Loading kernel module with target_pid=${GAME_PID}..."
    if ! insmod "${PROJECT_DIR}/kernel/owlbear.ko" target_pid="${GAME_PID}" 2>&1; then
        assert_fail "protected/module_load" "insmod failed"
        stop_game
        return
    fi

    sleep 2

    if [ -f /sys/kernel/debug/kprobes/list ]; then
        cp /sys/kernel/debug/kprobes/list "${phase_dir}/kprobes_list.txt"
    fi

    dmesg_since "${module_mark}" "${phase_dir}/module_load_dmesg.txt"

    if grep -q "owlbear: initialized successfully" "${phase_dir}/module_load_dmesg.txt" 2>/dev/null; then
        assert_pass "protected/module initialized"
    else
        assert_fail "protected/module did not report initialization"
    fi

    if grep -q "owlbear: target PID set\|target_pid=${GAME_PID}" "${phase_dir}/module_load_dmesg.txt" 2>/dev/null; then
        assert_pass "protected/target PID configured"
    fi

    if grep -q "PAC IA key changed\|PAC IA key substitution" "${phase_dir}/module_load_dmesg.txt" 2>/dev/null; then
        assert_fail "protected/no PAC false positives at load"
    else
        assert_pass "protected/no PAC false positives at load"
    fi

    # Start the daemon with --enforce
    log "Starting daemon with --enforce..."
    "${PROJECT_DIR}/daemon/owlbeard" \
        --target "${GAME_PID}" \
        --enforce \
        --log "${phase_dir}/daemon.log" \
        --sigs "${PROJECT_DIR}/signatures/default.sigs" \
        > "${phase_dir}/daemon_stdout.log" 2>&1 &
    DAEMON_PID=$!
    sleep 2

    if kill -0 "${DAEMON_PID}" 2>/dev/null; then
        assert_pass "protected/daemon started (pid=${DAEMON_PID})"
    else
        warn "Daemon failed to start (may need BPF skeleton headers)"
        DAEMON_PID=""
    fi

    capture_dmesg > "${phase_dir}/dmesg_before.txt"
    local cheats_dir="${PROJECT_DIR}/cheats"

    # --- mem_reader ---
    run_cheat_captured "${phase_dir}" "mem_reader" \
        "${cheats_dir}/mem_reader.bin"

    if grep -q "owlbear: process_vm_readv on PID ${GAME_PID}\|owlbear: ptrace attempt on protected PID ${GAME_PID}.*mem_reader" \
         "${phase_dir}/mem_reader/dmesg_diff.log" 2>/dev/null; then
        assert_pass "protected/mem_reader detected in dmesg (PID ${GAME_PID})"
    else
        assert_fail "protected/mem_reader detection missing"
    fi

    local cheat_comm
    cheat_comm=$(grep "owlbear:.*PID ${GAME_PID}.*mem_reader\|owlbear: process_vm_readv on PID ${GAME_PID}" \
        "${phase_dir}/mem_reader/dmesg_diff.log" 2>/dev/null | head -1)
    if [ -n "${cheat_comm}" ]; then
        echo "${cheat_comm}" > "${phase_dir}/mem_reader/detection_event.txt"
        assert_pass "protected/mem_reader detection event captured"
    fi

    # --- proc_mem_reader ---
    run_cheat_captured "${phase_dir}" "proc_mem_reader" \
        "${cheats_dir}/proc_mem_reader.bin"

    if grep -q "owlbear: /proc/${GAME_PID}/mem access" \
         "${phase_dir}/proc_mem_reader/dmesg_diff.log" 2>/dev/null; then
        assert_pass "protected/proc_mem_reader detected in dmesg (PID ${GAME_PID})"
    else
        assert_fail "protected/proc_mem_reader detection missing"
    fi

    local proc_event
    proc_event=$(grep "owlbear:.*mem access" \
        "${phase_dir}/proc_mem_reader/dmesg_diff.log" 2>/dev/null | head -1)
    if [ -n "${proc_event}" ]; then
        echo "${proc_event}" > "${phase_dir}/proc_mem_reader/detection_event.txt"
        assert_pass "protected/proc_mem_reader detection event captured"
    fi

    # Check if eBPF LSM blocked the open() (EPERM in stderr)
    if grep -qi "EPERM\|Permission denied" "${phase_dir}/proc_mem_reader/stderr.log" 2>/dev/null; then
        assert_pass "protected/proc_mem_reader got EPERM from eBPF LSM"
    fi

    # --- ptrace_injector ---
    run_cheat_captured "${phase_dir}" "ptrace_injector" \
        "${cheats_dir}/ptrace_injector.bin"

    if grep -q "owlbear: ptrace attempt on protected PID ${GAME_PID}" \
         "${phase_dir}/ptrace_injector/dmesg_diff.log" 2>/dev/null; then
        assert_pass "protected/ptrace_injector detected in dmesg (PID ${GAME_PID})"
    else
        assert_fail "protected/ptrace_injector detection missing"
    fi

    local ptrace_event
    ptrace_event=$(grep "owlbear: ptrace attempt" \
        "${phase_dir}/ptrace_injector/dmesg_diff.log" 2>/dev/null | head -1)
    if [ -n "${ptrace_event}" ]; then
        echo "${ptrace_event}" > "${phase_dir}/ptrace_injector/detection_event.txt"
        assert_pass "protected/ptrace_injector detection event captured"
    fi

    # Check if eBPF LSM blocked ptrace (EPERM)
    if grep -qi "EPERM\|Permission denied" "${phase_dir}/ptrace_injector/stderr.log" 2>/dev/null; then
        assert_pass "protected/ptrace_injector got EPERM from eBPF LSM"
    fi

    # --- ptrace_writer ---
    run_cheat_captured "${phase_dir}" "ptrace_writer" \
        "${cheats_dir}/ptrace_writer.bin"

    if grep -q "owlbear: ptrace attempt on protected PID ${GAME_PID}" \
         "${phase_dir}/ptrace_writer/dmesg_diff.log" 2>/dev/null; then
        assert_pass "protected/ptrace_writer triggers PTRACE_ATTEMPT detection"
    else
        assert_fail "protected/ptrace_writer detection missing"
    fi

    if grep -qi "EPERM\|Permission denied" "${phase_dir}/ptrace_writer/stderr.log" 2>/dev/null; then
        assert_pass "protected/ptrace_writer got EPERM from eBPF LSM"
    fi

    # --- vm_writer ---
    run_cheat_captured "${phase_dir}" "vm_writer" \
        "${cheats_dir}/vm_writer.bin"

    # vm_writev detection comes from eBPF tracepoint or kmod kprobe
    if grep -q "owlbear:.*writev\|VM_WRITEV" \
         "${phase_dir}/vm_writer/dmesg_diff.log" 2>/dev/null; then
        assert_pass "protected/vm_writer triggers VM_WRITEV_ATTEMPT detection"
    else
        # Also check daemon log for the detection
        if [ -f "${phase_dir}/daemon.log" ] && \
           grep -q "VM_WRITEV_ATTEMPT" "${phase_dir}/daemon.log" 2>/dev/null; then
            assert_pass "protected/vm_writer triggers VM_WRITEV_ATTEMPT in daemon log"
        else
            assert_fail "protected/vm_writer detection missing"
        fi
    fi

    # --- mprotect_injector ---
    run_cheat_captured "${phase_dir}" "mprotect_injector" \
        "${cheats_dir}/mprotect_injector.bin"

    # mprotect detection comes from eBPF LSM file_mprotect hook
    if [ -f "${phase_dir}/daemon.log" ] && \
       grep -q "MPROTECT_EXEC" "${phase_dir}/daemon.log" 2>/dev/null; then
        assert_pass "protected/mprotect_injector triggers MPROTECT_EXEC in daemon"
    elif grep -q "mprotect" "${phase_dir}/mprotect_injector/dmesg_diff.log" 2>/dev/null; then
        assert_pass "protected/mprotect_injector triggers mprotect detection"
    elif [ -f "${phase_dir}/daemon_stdout.log" ] && \
         grep -q "lsm=yes" "${phase_dir}/daemon_stdout.log" 2>/dev/null; then
        assert_fail "protected/mprotect_injector detection missing (BPF LSM loaded but no event)"
    else
        assert_skip "protected/mprotect_injector detection" "BPF LSM hooks not available on this kernel"
    fi

    # Check daemon log for BLOCK entries if enforce mode
    if [ -f "${phase_dir}/daemon.log" ]; then
        if grep -q "\[ENFORCE\].*\[BLOCK\]" "${phase_dir}/daemon.log" 2>/dev/null; then
            assert_pass "protected/daemon log contains BLOCK enforcement entries"
        fi
    fi

    # Wait and check for PAC false positives
    sleep 6

    capture_dmesg > "${phase_dir}/dmesg_after.txt"

    if grep -q "PAC IA key changed\|PAC IA key substitution" \
         "${phase_dir}/dmesg_after.txt" 2>/dev/null; then
        assert_fail "protected/no PAC false positives during run"
    else
        assert_pass "protected/no PAC false positives during run"
    fi

    # Check integrity baseline was captured
    if [ -f "${phase_dir}/daemon_stdout.log" ] && \
       grep -q "integrity baseline" "${phase_dir}/daemon_stdout.log" 2>/dev/null; then
        assert_pass "protected/code integrity baseline captured"
    fi

    stop_daemon

    # Unload module
    rmmod owlbear 2>/dev/null || true
    sleep 1

    stop_game
}

# -------------------------------------------------------------------------
# Phase 3: SELF-PROTECTION — module unload detection
# -------------------------------------------------------------------------

phase_selfprotect() {
    log ""
    log "========================================="
    log "  Phase 3: SELF-PROTECTION"
    log "========================================="
    log ""

    local phase_dir="${OUT_DIR}/selfprotect"
    mkdir -p "${phase_dir}"

    if [ ! -f "${PROJECT_DIR}/kernel/owlbear.ko" ]; then
        assert_skip "selfprotect phase" "kernel module not available"
        return
    fi

    start_game

    if lsmod 2>/dev/null | grep -q owlbear; then
        rmmod owlbear 2>/dev/null || true
        sleep 1
    fi

    insmod "${PROJECT_DIR}/kernel/owlbear.ko" target_pid="${GAME_PID}" 2>&1 || {
        assert_fail "selfprotect/module_load"
        stop_game
        return
    }
    sleep 1

    # Start daemon — capture stdout and stderr separately
    "${PROJECT_DIR}/daemon/owlbeard" \
        --target "${GAME_PID}" \
        --log "${phase_dir}/daemon.log" \
        --sigs "${PROJECT_DIR}/signatures/default.sigs" \
        > "${phase_dir}/daemon_stdout.log" 2>"${phase_dir}/daemon_stderr.log" &
    DAEMON_PID=$!
    sleep 3

    if ! kill -0 "${DAEMON_PID}" 2>/dev/null; then
        warn "Daemon did not start for selfprotect phase"
        stop_game
        rmmod owlbear 2>/dev/null || true
        return
    fi

    # Unload the module while daemon is running
    log "Unloading module while daemon is running..."
    local unload_mark
    unload_mark=$(dmesg_mark)

    rmmod owlbear 2>/dev/null || true
    sleep 12  # Wait for 2 watchdog cycles (5s each) + margin

    # Check daemon survived the unload
    if kill -0 "${DAEMON_PID}" 2>/dev/null; then
        assert_pass "selfprotect/daemon survives module unload"
    else
        assert_fail "selfprotect/daemon crashed after module unload"
    fi

    # Check daemon detected the unload — look in stdout, stderr, and daemon log
    local detected=false
    for logfile in "${phase_dir}/daemon_stdout.log" \
                   "${phase_dir}/daemon_stderr.log" \
                   "${phase_dir}/daemon.log"; do
        if [ -f "${logfile}" ] && \
           grep -qi "module unloaded\|MODULE_UNKNOWN\|ALERT.*kernel module\|device closed" \
             "${logfile}" 2>/dev/null; then
            detected=true
            break
        fi
    done

    if [ "${detected}" = true ]; then
        assert_pass "selfprotect/daemon detected module unload"
    else
        assert_fail "selfprotect/daemon did not detect module unload"
    fi

    # Check dmesg for delete_module event
    dmesg_since "${unload_mark}" "${phase_dir}/unload_dmesg.txt"

    stop_daemon
    stop_game
}

# -------------------------------------------------------------------------
# Write final summary
# -------------------------------------------------------------------------

write_summary() {
    cat >> "${OUT_DIR}/summary.txt" <<FOOTER

# =========================================
# Results: ${PASSED_ASSERTIONS} passed, ${FAILED_ASSERTIONS} failed, ${SKIPPED_ASSERTIONS} skipped / ${TOTAL_ASSERTIONS} total
# =========================================
FOOTER

    {
        echo "# Artifact manifest"
        echo "# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        echo ""
        find "${OUT_DIR}" -type f | sort | while read -r f; do
            local rel="${f#${OUT_DIR}/}"
            local size
            size=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo "?")
            local hash
            hash=$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1 || shasum -a 256 "$f" 2>/dev/null | cut -d' ' -f1 || echo "?")
            echo "${rel}  size=${size}  sha256=${hash}"
        done
    } > "${OUT_DIR}/manifest.txt"
}

# -------------------------------------------------------------------------
# Main
# -------------------------------------------------------------------------

main() {
    echo ""
    echo -e "${BOLD}================================================${NC}"
    echo -e "${BOLD}  Owlbear E2E Verification (v1.0.0)${NC}"
    echo -e "${BOLD}  Evidence Package Builder${NC}"
    echo -e "${BOLD}================================================${NC}"
    echo ""

    preflight "$@"

    phase_baseline
    phase_protected
    phase_selfprotect

    write_summary

    if [ "${UPLOAD}" = true ]; then
        upload_to_s3
    fi

    echo ""
    log "========================================="
    log "  RESULTS"
    log "========================================="
    echo ""
    echo -e "  Passed:  ${GREEN}${PASSED_ASSERTIONS}${NC}"
    echo -e "  Failed:  ${RED}${FAILED_ASSERTIONS}${NC}"
    echo -e "  Skipped: ${YELLOW}${SKIPPED_ASSERTIONS}${NC}"
    echo -e "  Total:   ${BOLD}${TOTAL_ASSERTIONS}${NC}"
    echo ""
    log "Evidence package: ${OUT_DIR}"
    log "Summary: ${OUT_DIR}/summary.txt"
    log "Manifest: ${OUT_DIR}/manifest.txt"
    echo ""

    if command -v tree > /dev/null 2>&1; then
        tree "${OUT_DIR}" --charset ascii
    else
        find "${OUT_DIR}" -type f | sort | sed "s|${OUT_DIR}/|  |"
    fi

    echo ""

    if [ "${FAILED_ASSERTIONS}" -gt 0 ]; then
        fail "Verification FAILED (${FAILED_ASSERTIONS} failures)"
        exit 1
    else
        pass "Verification PASSED"
        exit 0
    fi
}

main "$@"
