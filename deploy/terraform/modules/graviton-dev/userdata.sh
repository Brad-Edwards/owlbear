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
  linux-tools-$(uname -r) \
  libelf-dev \
  libcurl4-openssl-dev \
  libncurses-dev \
  libbpf-dev \
  strace \
  jq \
  tmux \
  htop \
  zlib1g-dev \
  libssl-dev \
  unzip

# AWS CLI v2
if ! command -v aws &>/dev/null; then
  curl -sf "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" -o /tmp/awscliv2.zip
  unzip -q /tmp/awscliv2.zip -d /tmp
  /tmp/aws/install
  rm -rf /tmp/awscliv2.zip /tmp/aws
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
