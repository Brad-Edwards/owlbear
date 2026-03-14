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

# Build everything including tests and kernel module
cd owlbear
sudo -u ec2-user make daemon game cheats || true
sudo -u ec2-user make -C tests all || true
make -C kernel || true

echo "=== Setup complete ==="
echo "Connect via: aws ssm start-session --target $(curl -s http://169.254.169.254/latest/meta-data/instance-id)"
