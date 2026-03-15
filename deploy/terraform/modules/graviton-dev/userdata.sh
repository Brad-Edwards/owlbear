#!/bin/bash
set -euo pipefail

exec > /var/log/userdata.log 2>&1

echo "=== Owlbear Graviton dev instance setup ==="

# System updates
dnf update -y -q

# Build essentials
dnf install -y -q \
  gcc \
  clang \
  llvm \
  lld \
  make \
  git \
  kernel-devel \
  kernel-headers \
  elfutils-libelf-devel \
  libcurl-devel \
  ncurses-devel \
  bpftool \
  libbpf-devel \
  strace \
  jq \
  tmux \
  htop

# Clone or update repo
cd /home/ec2-user
if [ ! -d owlbear ]; then
  git clone ${github_repo_url} owlbear
  chown -R ec2-user:ec2-user owlbear
else
  cd owlbear
  sudo -u ec2-user git pull --ff-only || true
  cd ..
fi

# Enable BPF LSM — required for eBPF enforcement hooks (file_mprotect, ptrace_access_check, file_open)
# AL2023 kernel has CONFIG_BPF_LSM=y but needs 'bpf' in the active LSM list.
GRUB_FILE="/etc/default/grub"
if ! grep -q "lsm=.*bpf" "$GRUB_FILE" 2>/dev/null; then
  if grep -q 'GRUB_CMDLINE_LINUX=' "$GRUB_FILE"; then
    sed -i 's/GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 lsm=lockdown,capability,yama,bpf"/' "$GRUB_FILE"
  else
    echo 'GRUB_CMDLINE_LINUX="lsm=lockdown,capability,yama,bpf"' >> "$GRUB_FILE"
  fi
  grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null || true
  echo "BPF LSM added to boot params — will take effect on next reboot"
fi

# Build everything: eBPF first (generates skeleton headers), then userspace, then kernel
cd owlbear
sudo -u ec2-user make -C ebpf || true
sudo -u ec2-user make daemon game cheats || true
sudo -u ec2-user make -C tests unit || true
make -C kernel || true

echo "=== Setup complete ==="
echo "Connect via: aws ssm start-session --target $(curl -s http://169.254.169.254/latest/meta-data/instance-id)"
