#!/usr/bin/env bash
# Prepare an isolated native ARM64 image. This does not run a qualification.
set -euo pipefail

revision=${1:?Usage: prepare-image.sh <owlbear commit>}
if [[ ! "$revision" =~ ^[a-f0-9]{40}$ ]] || [[ $(id -u) != 0 ]] || [[ $(uname -m) != aarch64 ]]; then
    echo 'A full commit, root, and native ARM64 are required.' >&2
    exit 1
fi
if [[ -e /opt/owlbear/source || -e /opt/owlbear/artifacts || -e /opt/owlbear/releases ]]; then
    echo 'Refusing to replace an existing Owlbear installation.' >&2
    exit 1
fi
kernel=$(uname -r)
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
    build-essential clang llvm git python3 libbpf-dev libelf-dev zlib1g-dev \
    libssl-dev libcurl4-openssl-dev libncurses-dev kmod binutils \
    "linux-headers-$kernel" "linux-tools-$kernel" linux-tools-generic
mkdir -p /opt/owlbear
chmod 0755 /opt/owlbear
git clone --filter=blob:none --no-checkout https://github.com/Brad-Edwards/owlbear.git /opt/owlbear/source
git -C /opt/owlbear/source checkout --detach "$revision"
cd /opt/owlbear/source
bpftool=$(find /usr/lib -maxdepth 4 -type f -name bpftool -print -quit)
if [[ -z "$bpftool" ]]; then
    echo 'No packaged bpftool binary is available.' >&2
    exit 1
fi
python3 scripts/research-artifact.py build --bpftool "$bpftool" --output /opt/owlbear/artifacts --jobs 4
archive=$(find /opt/owlbear/artifacts -maxdepth 1 -name '*.tar.gz' -print -quit)
mkdir -p /opt/owlbear/releases/qualification
tar -xzf "$archive" -C /opt/owlbear/releases/qualification --strip-components=1
python3 scripts/research-artifact.py verify /opt/owlbear/releases/qualification

# Retain the existing configured LSM order and enable BPF for the next boot.
lsm=$(sed -n 's/^CONFIG_LSM="\(.*\)"$/\1/p' "/boot/config-$kernel")
if [[ -z "$lsm" || ! "$lsm" =~ ^[a-z_,]+$ ]]; then
    echo 'The kernel LSM configuration is unavailable.' >&2
    exit 1
fi
if [[ ,$lsm, != *,bpf,* ]]; then
    lsm=$lsm,bpf
fi
# Preserve the variable for GRUB's configuration loader, rather than this shell.
# shellcheck disable=SC2016
printf 'GRUB_CMDLINE_LINUX="${GRUB_CMDLINE_LINUX} lsm=%s"\n' "$lsm" > /etc/default/grub.d/99-owlbear-lsm.cfg
update-grub
install -d -m 0755 /opt/owlbear/qualification
install -m 0644 qualification/bigrae/check-memory.py qualification/bigrae/baseline.py /opt/owlbear/qualification/
install -m 0644 deploy/gcp/owlbear-qualification-baseline.service deploy/gcp/owlbear-qualification-target.service /etc/systemd/system/
systemctl daemon-reload
printf '%s\n' 'Image prepared. Reboot and verify the kernel and active BPF LSM.'
printf '%s\n' 'Follow README.md to enable the workload without starting it before image capture.'
