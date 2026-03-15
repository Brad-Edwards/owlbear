#!/bin/bash
set -euo pipefail

exec > /var/log/userdata.log 2>&1

echo "=== Owlbear Graviton dev instance setup (Ubuntu 24.04) ==="

# System updates
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq

# Build essentials
apt-get install -y -qq \
  gcc \
  clang \
  llvm \
  lld \
  make \
  git \
  linux-headers-$(uname -r) \
  libelf-dev \
  libcurl4-openssl-dev \
  libncurses-dev \
  libbpf-dev \
  bpftool \
  strace \
  jq \
  tmux \
  htop \
  zlib1g-dev \
  awscli

# SSM agent (Ubuntu AMI may not have it)
if ! systemctl is-active --quiet amazon-ssm-agent 2>/dev/null; then
  snap install amazon-ssm-agent --classic 2>/dev/null || true
fi

# Clone or update repo
cd /home/ubuntu
if [ ! -d owlbear ]; then
  git clone ${github_repo_url} owlbear
  chown -R ubuntu:ubuntu owlbear
else
  cd owlbear
  sudo -u ubuntu git pull --ff-only || true
  cd ..
fi

# Build everything: eBPF first (generates skeleton headers), then userspace, then kernel
cd owlbear
sudo -u ubuntu make -C ebpf || true
sudo -u ubuntu make daemon game cheats || true
sudo -u ubuntu make -C tests unit || true
make -C kernel || true

echo "=== Setup complete ==="
echo "Kernel: $(uname -r)"
echo "LSM: $(cat /sys/kernel/security/lsm 2>/dev/null || echo unknown)"
echo "Connect via: aws ssm start-session --target $(curl -s http://169.254.169.254/latest/meta-data/instance-id)"
