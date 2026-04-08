#!/usr/bin/env bash

# Exit on error, undefined variable, or failed pipe
set -euo pipefail

echo "[*] Starting Ansible setup..."

# Ensure script is run as root (required for package installs)
if [[ "$EUID" -ne 0 ]]; then
  echo "[!] Please run this script as root or with sudo."
  exit 1
fi

# Detect Linux distribution using os-release
if [[ -f /etc/os-release ]]; then
  . /etc/os-release
  OS_FAMILY="${ID_LIKE:-$ID}"  # fallback if ID_LIKE not set
  OS_ID="${ID}"
else
  echo "[!] Could not detect Linux distribution."
  exit 1
fi

# Install dependencies + Ansible for Debian/Ubuntu
install_debian() {
  echo "[*] Detected Debian/Ubuntu-based system"

  # Update package list
  apt update

  # Install core dependencies for Ansible + general tooling
  apt install -y \
    software-properties-common \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    unzip \
    rsync \
    sshpass \
    openssh-client \
    ca-certificates

  # Install Ansible via apt, fallback to pip if needed
  apt install -y ansible || {
    echo "[*] apt ansible package failed, trying pip..."
    python3 -m pip install --break-system-packages ansible
  }
}

# Install for RHEL / Rocky / CentOS / AlmaLinux
install_rhel() {
  echo "[*] Detected RHEL-based system"

  # Choose correct package manager
  if command -v dnf >/dev/null 2>&1; then
    PKG="dnf"
  else
    PKG="yum"
  fi

  # Enable EPEL (extra packages repo)
  $PKG install -y epel-release || true

  # Install dependencies
  $PKG install -y \
    python3 \
    python3-pip \
    git \
    curl \
    wget \
    unzip \
    rsync \
    sshpass \
    openssh-clients \
    ca-certificates

  # Install Ansible, fallback to pip
  $PKG install -y ansible || {
    echo "[*] repo ansible package failed, trying pip..."
    python3 -m pip install ansible
  }
}

# Fedora install
install_fedora() {
  echo "[*] Detected Fedora"

  dnf install -y \
    python3 \
    python3-pip \
    git \
    curl \
    wget \
    unzip \
    rsync \
    sshpass \
    openssh-clients \
    ca-certificates \
    ansible
}

# Arch install
install_arch() {
  echo "[*] Detected Arch-based system"

  pacman -Sy --noconfirm \
    python \
    python-pip \
    git \
    curl \
    wget \
    unzip \
    rsync \
    sshpass \
    openssh \
    ca-certificates \
    ansible
}

# SUSE install
install_suse() {
  echo "[*] Detected SUSE-based system"

  zypper refresh
  zypper install -y \
    python3 \
    python3-pip \
    git \
    curl \
    wget \
    unzip \
    rsync \
    sshpass \
    openssh-clients \
    ca-certificates \
    ansible
}

# Route to correct install function based on OS
case "$OS_ID" in
  ubuntu|debian)
    install_debian
    ;;
  rocky|rhel|centos|almalinux)
    install_rhel
    ;;
  fedora)
    install_fedora
    ;;
  arch|manjaro)
    install_arch
    ;;
  opensuse*|sles)
    install_suse
    ;;
  *)
    # Fallback using OS family detection
    if [[ "$OS_FAMILY" == *debian* ]]; then
      install_debian
    elif [[ "$OS_FAMILY" == *rhel* ]] || [[ "$OS_FAMILY" == *fedora* ]]; then
      install_rhel
    else
      echo "[!] Unsupported distro: $OS_ID"
      exit 1
    fi
    ;;
esac

echo "[*] Verifying install..."

# Confirm Ansible is installed
if command -v ansible >/dev/null 2>&1; then
  ansible --version
else
  echo "[!] Ansible install failed."
  exit 1
fi

# Install common collections used in Windows + enterprise environments
echo "[*] Installing common Ansible collections..."
ansible-galaxy collection install \
  ansible.windows \
  community.general \
  community.windows \
  microsoft.ad || true

echo "[*] Setup complete."
echo "[*] Test with: ansible localhost -m ping -c local"