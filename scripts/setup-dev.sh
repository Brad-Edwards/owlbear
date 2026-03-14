#!/usr/bin/env bash
# Owlbear development environment setup
#
# Installs all build dependencies for ARM64 development.
# Supports: Ubuntu/Debian (native ARM64 or cross-compilation from x86_64)
#
# Usage: sudo ./scripts/setup-dev.sh

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"

log_info()  { echo "[${SCRIPT_NAME}] INFO:  $*"; }
log_error() { echo "[${SCRIPT_NAME}] ERROR: $*" >&2; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

detect_arch() {
    local arch
    arch="$(uname -m)"
    log_info "Detected architecture: ${arch}"
    echo "${arch}"
}

install_common_deps() {
    log_info "Installing common build dependencies..."
    apt-get update -qq

    apt-get install -y --no-install-recommends \
        build-essential \
        clang \
        llvm \
        lld \
        pkg-config \
        libelf-dev \
        libcurl4-openssl-dev \
        libncurses-dev \
        libyaml-dev \
        linux-tools-common \
        bpftool \
        jq \
        git \
        curl \
        ca-certificates
}

install_arm64_native_deps() {
    log_info "Installing ARM64-native kernel development headers..."
    apt-get install -y --no-install-recommends \
        linux-headers-"$(uname -r)" \
        libbpf-dev
}

install_cross_compile_deps() {
    log_info "Installing cross-compilation toolchain for ARM64..."
    apt-get install -y --no-install-recommends \
        gcc-aarch64-linux-gnu \
        binutils-aarch64-linux-gnu \
        libbpf-dev

    log_info "Cross-compiler installed: aarch64-linux-gnu-gcc"
    log_info "Note: For kernel module cross-compilation, you need ARM64 kernel headers."
    log_info "  Set KDIR to point to the ARM64 kernel source tree."
}

install_terraform() {
    if command -v terraform &>/dev/null; then
        log_info "Terraform already installed: $(terraform version -json | jq -r '.terraform_version')"
        return
    fi

    log_info "Installing Terraform..."
    local tf_version="1.7.5"
    local arch
    arch="$(uname -m)"

    case "${arch}" in
        x86_64)  tf_arch="amd64" ;;
        aarch64) tf_arch="arm64" ;;
        *)       log_error "Unsupported architecture for Terraform: ${arch}"; return 1 ;;
    esac

    curl -fsSL "https://releases.hashicorp.com/terraform/${tf_version}/terraform_${tf_version}_linux_${tf_arch}.zip" -o /tmp/terraform.zip
    unzip -o /tmp/terraform.zip -d /usr/local/bin/
    rm -f /tmp/terraform.zip
    log_info "Terraform ${tf_version} installed"
}

verify_installation() {
    log_info "Verifying installation..."

    local tools=("gcc" "clang" "llvm-objdump" "make" "pkg-config")
    local missing=()

    for tool in "${tools[@]}"; do
        if ! command -v "${tool}" &>/dev/null; then
            missing+=("${tool}")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing tools: ${missing[*]}"
        exit 1
    fi

    log_info "All required tools are available"
}

print_summary() {
    echo ""
    echo "============================================"
    echo "  Owlbear development environment ready"
    echo "============================================"
    echo ""
    echo "  gcc:        $(gcc --version | head -1)"
    echo "  clang:      $(clang --version | head -1)"
    echo "  make:       $(make --version | head -1)"

    if command -v aarch64-linux-gnu-gcc &>/dev/null; then
        echo "  cross-gcc:  $(aarch64-linux-gnu-gcc --version | head -1)"
    fi

    if command -v bpftool &>/dev/null; then
        echo "  bpftool:    $(bpftool version 2>/dev/null | head -1 || echo 'installed')"
    fi

    if command -v terraform &>/dev/null; then
        echo "  terraform:  $(terraform version -json 2>/dev/null | jq -r '.terraform_version' || echo 'installed')"
    fi

    echo ""
    echo "Next steps:"
    echo "  make all          # Build everything"
    echo "  make kernel       # Build kernel module only"
    echo "  make test         # Run unit tests"
    echo ""
}

main() {
    check_root

    local arch
    arch="$(detect_arch)"

    install_common_deps

    case "${arch}" in
        aarch64)
            install_arm64_native_deps
            ;;
        x86_64)
            install_cross_compile_deps
            ;;
        *)
            log_error "Unsupported architecture: ${arch}"
            exit 1
            ;;
    esac

    install_terraform
    verify_installation
    print_summary
}

main "$@"
