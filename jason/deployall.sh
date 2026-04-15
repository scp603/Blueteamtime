#!/bin/bash
# Nine-Tailed Fox - Deploy All
# Clones team repos, runs all scripts, then removes itself and the repos.

REPO_URL="https://github.com/JasonHyde9/deploy.git"
REPO_DIR="/tmp/ninetailedfox_deploy"

REPO2_URL="https://github.com/scp603/Blueteamtime.git"
REPO2_DIR="/tmp/blueteamtime_deploy"

SELF="$(realpath "$0")"

echo "=== Nine-Tailed Fox: Deploy All ==="

# --- Repo 1: JasonHyde9/deploy ---

if [ -d "$REPO_DIR" ]; then
    echo "[!] Stale repo directory found, removing..."
    rm -rf "$REPO_DIR"
fi

echo "[+] Cloning $REPO_URL..."
git clone "$REPO_URL" "$REPO_DIR" 2>/dev/null

if [ ! -d "$REPO_DIR" ]; then
    echo "[-] Clone failed: $REPO_URL"
    exit 1
fi

echo "[+] Clone successful."
chmod +x "$REPO_DIR/fakeflags.sh"
chmod +x "$REPO_DIR/openvpn-harden.sh"

echo ""
echo "--- Running: openvpn-harden.sh ---"
bash "$REPO_DIR/openvpn-harden.sh"
echo "--- Done: openvpn-harden.sh ---"

echo ""
echo "--- Running: fakeflags.sh ---"
bash "$REPO_DIR/fakeflags.sh"
echo "--- Done: fakeflags.sh ---"

echo "[+] Cleaning up repo 1..."
rm -rf "$REPO_DIR"

# --- Repo 2: scp603/Blueteamtime ---

if [ -d "$REPO2_DIR" ]; then
    echo "[!] Stale repo 2 directory found, removing..."
    rm -rf "$REPO2_DIR"
fi

echo ""
echo "[+] Cloning $REPO2_URL..."
git clone "$REPO2_URL" "$REPO2_DIR" 2>/dev/null

if [ ! -d "$REPO2_DIR" ]; then
    echo "[-] Clone failed: $REPO2_URL"
    exit 1
fi

echo "[+] Clone successful."

TRIAGE_SCRIPT="$REPO2_DIR/odessa/triage/triage-rocky.sh"
LINPASCHA_SCRIPT="$REPO2_DIR/gavin/linpascha.sh"

if [ ! -f "$TRIAGE_SCRIPT" ]; then
    echo "[-] triage-rocky.sh not found at expected path: $TRIAGE_SCRIPT"
    rm -rf "$REPO2_DIR"
    exit 1
fi

if [ ! -f "$LINPASCHA_SCRIPT" ]; then
    echo "[-] linpascha.sh not found at expected path: $LINPASCHA_SCRIPT"
    rm -rf "$REPO2_DIR"
    exit 1
fi

chmod +x "$TRIAGE_SCRIPT"
chmod +x "$LINPASCHA_SCRIPT"

echo ""
echo "--- Running: triage-rocky.sh ---"
bash "$TRIAGE_SCRIPT"
echo "--- Done: triage-rocky.sh ---"

echo ""
echo "--- Running: linpascha.sh ---"
bash "$LINPASCHA_SCRIPT"
echo "--- Done: linpascha.sh ---"

echo "[+] Cleaning up repo 2..."
rm -rf "$REPO2_DIR"

# --- Cleanup ---
echo ""
echo "[+] Removing self ($SELF)..."
rm -f "$SELF"

echo ""
echo "[+] Deploy complete. All repos and deployer removed."