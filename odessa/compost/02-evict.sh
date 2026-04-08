#!/usr/bin/env bash
# =============================================================================
# 02-evict.sh  [LEVEL 2 — SURGICAL REMOVAL]
# Removes all Party Rocket artifacts without full host rebuild.
# Safe to run on a live system — does NOT kill SSH daemon.
#
# Removes:
#   1.  PAM hook from /etc/pam.d/common-auth (and any other PAM file)
#   2.  Beacon binary /usr/local/bin/ssh-auth-check (unfreezes chattr first)
#   3.  Credential log /var/lib/systemd/ssh-service.log (collect evidence first)
#   4.  Self-healing cron "System-Svc-Monitor" from all crontabs
#   5.  Bashrc PROMPT_COMMAND hijack from all user home dirs
#   6.  Hidden command logs .hidden_log and .system_data_cache
#   7.  Restores SSH config: PasswordAuthentication no, retests PAM
#
# Run as root. Keep a second session open.
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
YLW='\033[1;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
BLD='\033[1m'
RST='\033[0m'

[[ $EUID -ne 0 ]] && { echo "Run as root" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="$SCRIPT_DIR/evict_$(hostname)_$(date +%Y%m%d_%H%M%S).log"
EVIDENCE="$SCRIPT_DIR/evict_evidence_$(date +%Y%m%d_%H%M%S)"

log()  { echo -e "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
ok()   { echo -e "${GRN}[OK]${RST}   $*" | tee -a "$LOG"; }
warn() { echo -e "${YLW}[WARN]${RST} $*" | tee -a "$LOG"; }
hit()  { echo -e "${RED}[EVICT]${RST} $*" | tee -a "$LOG"; }

log "${BLD}=== Party Rocket Eviction — $(hostname) ===${RST}"
log "Evidence dir: $EVIDENCE"
mkdir -p "$EVIDENCE"

# =============================================================================
# 1. KILL SELF-HEALING CRON FIRST
#    If we remove the PAM hook but leave the cron, it re-injects within 60s.
#    Remove the cron before anything else.
# =============================================================================
log "\n--- [1/7] Removing self-healing cron (System-Svc-Monitor) ---"

# Root crontab
if crontab -l 2>/dev/null | grep -qE "ssh-auth-check|System-Svc-Monitor"; then
    crontab -l 2>/dev/null | tee "$EVIDENCE/root_crontab.bak" > /dev/null
    crontab -l 2>/dev/null \
        | grep -vE "ssh-auth-check|System-Svc-Monitor" \
        | crontab -
    hit "Removed malicious entries from root crontab"
fi

# All user crontab spools
for f in /var/spool/cron/crontabs/*; do
    [[ -f "$f" ]] || continue
    if grep -qE "ssh-auth-check|System-Svc-Monitor" "$f" 2>/dev/null; then
        cp "$f" "$EVIDENCE/$(basename $f)_crontab.bak"
        chattr -i "$f" 2>/dev/null || true
        grep -vE "ssh-auth-check|System-Svc-Monitor" "$f" > "${f}.clean"
        mv "${f}.clean" "$f"
        hit "Removed malicious entries from $f"
    fi
done

# /etc/cron.d/
for f in /etc/cron.d/*; do
    [[ -f "$f" ]] || continue
    if grep -qE "ssh-auth-check|System-Svc-Monitor" "$f" 2>/dev/null; then
        cp "$f" "$EVIDENCE/$(basename $f)_crond.bak"
        chattr -i "$f" 2>/dev/null || true
        sed -i -E '/ssh-auth-check|System-Svc-Monitor/d' "$f"
        hit "Removed malicious entries from $f"
    fi
done

# /etc/crontab
if grep -qE "ssh-auth-check|System-Svc-Monitor" /etc/crontab 2>/dev/null; then
    cp /etc/crontab "$EVIDENCE/crontab.bak"
    chattr -i /etc/crontab 2>/dev/null || true
    sed -i -E '/ssh-auth-check|System-Svc-Monitor/d' /etc/crontab
    hit "Removed malicious entries from /etc/crontab"
fi

ok "Cron sweep complete — self-healing mechanism disabled"

# =============================================================================
# 2. REMOVE PAM HOOK from /etc/pam.d/common-auth and all PAM configs
#    Line: auth optional pam_exec.so quiet expose_authtok /usr/local/bin/ssh-auth-check
# =============================================================================
log "\n--- [2/7] Removing PAM hook ---"

# Unfreeze PAM files if chattr'd
for f in /etc/pam.d/*; do
    chattr -i "$f" 2>/dev/null || true
done

for f in /etc/pam.d/*; do
    [[ -f "$f" ]] || continue
    if grep -q "ssh-auth-check" "$f" 2>/dev/null; then
        cp "$f" "$EVIDENCE/$(basename $f).pam.bak"
        sed -i '/ssh-auth-check/d' "$f"
        hit "Removed PAM hook from $f"
    fi
done

# Also remove any general pam_exec.so line that references scripts in /usr/local/bin
# (in case the attacker renamed the binary)
for f in /etc/pam.d/*; do
    [[ -f "$f" ]] || continue
    if grep -qE "pam_exec\.so.*expose_authtok.*/usr/local/bin/" "$f" 2>/dev/null; then
        cp "$f" "$EVIDENCE/$(basename $f).pam_exec.bak" 2>/dev/null || true
        sed -i -E '/pam_exec\.so.*expose_authtok.*\/usr\/local\/bin\//d' "$f"
        hit "Removed suspicious pam_exec.so hook from $f"
    fi
done

ok "PAM hook removal complete — no more password interception"

# =============================================================================
# 3. COLLECT EVIDENCE THEN REMOVE BEACON BINARY
#    /usr/local/bin/ssh-auth-check — immutable, must chattr -i first
# =============================================================================
log "\n--- [3/7] Removing beacon binary ---"

BEACON="/usr/local/bin/ssh-auth-check"
if [[ -f "$BEACON" ]]; then
    # Collect evidence
    cp -p "$BEACON" "$EVIDENCE/ssh-auth-check.evidence"
    sha256sum "$BEACON" | tee -a "$LOG"

    # Unfreeze
    chattr -i "$BEACON" 2>/dev/null && hit "Unfroze chattr +i on $BEACON" || true

    # Kill any running instances
    pkill -9 -f "ssh-auth-check" 2>/dev/null && hit "Killed running ssh-auth-check processes" || true

    # Remove
    rm -f "$BEACON"
    hit "Removed $BEACON"
else
    ok "$BEACON not present"
fi

# Broader sweep for renamed copies with same content
info() { echo -e "${CYN}[INFO]${RST} $*" | tee -a "$LOG"; }
info "Scanning /usr/local/bin/ for scripts referencing ssh-service.log..."
for f in /usr/local/bin/*; do
    [[ -f "$f" ]] || continue
    [[ "$f" == "$BEACON" ]] && continue
    if grep -q "ssh-service.log\|PAM_USER.*PAM_RHOST" "$f" 2>/dev/null; then
        cp -p "$f" "$EVIDENCE/$(basename $f).evidence"
        chattr -i "$f" 2>/dev/null || true
        rm -f "$f"
        hit "Removed renamed beacon copy: $f"
    fi
done

ok "Beacon binary removal complete"

# =============================================================================
# 4. COLLECT AND REMOVE CREDENTIAL LOG
#    /var/lib/systemd/ssh-service.log — world-readable (chmod 666)
#    Contains: timestamp | username | source_IP | plaintext_password
# =============================================================================
log "\n--- [4/7] Securing credential harvest log ---"

CREDLOG="/var/lib/systemd/ssh-service.log"
if [[ -f "$CREDLOG" ]]; then
    lines=$(wc -l < "$CREDLOG")
    hit "Credential log has $lines entries — collecting evidence"

    cp -p "$CREDLOG" "$EVIDENCE/ssh-service.log.evidence"
    chattr -i "$CREDLOG" 2>/dev/null || true
    chmod 600 "$EVIDENCE/ssh-service.log.evidence"

    # Zero out and remove the original (don't just delete — zero first to prevent recovery)
    shred -u "$CREDLOG" 2>/dev/null && hit "Shredded $CREDLOG" \
        || { rm -f "$CREDLOG"; hit "Removed $CREDLOG"; }

    warn "Evidence saved to $EVIDENCE/ssh-service.log.evidence — protect this file"
    warn "Credentials in this log are COMPROMISED — rotate affected accounts"
else
    ok "$CREDLOG not present"
fi

ok "Credential log removed"

# =============================================================================
# 5. CLEAN BASHRC HIJACK from all user home directories
#    Removes PROMPT_COMMAND lines referencing hidden_log or system_data_cache
# =============================================================================
log "\n--- [5/7] Cleaning bashrc PROMPT_COMMAND hijack ---"

for homedir in /root /home/*/; do
    homedir="${homedir%/}"
    [[ -d "$homedir" ]] || continue
    bashrc="$homedir/.bashrc"
    [[ -f "$bashrc" ]] || continue

    if grep -qE "hidden_log|system_data_cache" "$bashrc" 2>/dev/null; then
        cp "$bashrc" "$EVIDENCE/$(basename $homedir)_bashrc.bak"
        sed -i -E '/hidden_log|system_data_cache/d' "$bashrc"
        hit "Removed PROMPT_COMMAND hijack from $bashrc"
    fi

    # Remove hidden log files
    for hidden in "$homedir/.local/share/.hidden_log" "$homedir/.local/share/.system_data_cache"; do
        if [[ -f "$hidden" ]]; then
            cp "$hidden" "$EVIDENCE/" 2>/dev/null || true
            rm -f "$hidden"
            hit "Removed hidden command log: $hidden"
        fi
    done
done

ok "Bashrc cleanup complete"

# =============================================================================
# 6. RESTORE SSH CONFIG
#    Party Rocket sets PasswordAuthentication yes and UsePAM yes.
#    Restore PasswordAuthentication to no (after verifying key access exists).
# =============================================================================
log "\n--- [6/7] Restoring SSH configuration ---"

SSHD_CONFIG="/etc/ssh/sshd_config"
chattr -i "$SSHD_CONFIG" 2>/dev/null || true
cp "$SSHD_CONFIG" "$EVIDENCE/sshd_config.bak"

# Only disable password auth if keys exist — avoid self-lockout
if [[ -f /root/.ssh/authorized_keys ]] || ls /home/*/.ssh/authorized_keys 2>/dev/null | head -1 &>/dev/null; then
    sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' "$SSHD_CONFIG"
    grep -q "^PasswordAuthentication" "$SSHD_CONFIG" \
        || echo "PasswordAuthentication no" >> "$SSHD_CONFIG"
    hit "PasswordAuthentication set to no"
    warn "Verify key-based SSH access before closing this session"
else
    warn "No authorized_keys found — leaving PasswordAuthentication as-is to avoid lockout"
    warn "Add your SSH public key, then manually set PasswordAuthentication no"
fi

systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
ok "SSH restarted with cleaned config"

# =============================================================================
# 7. VERIFY REMOVAL
# =============================================================================
log "\n--- [7/7] Verification ---"

FAILURES=0

if grep -q "ssh-auth-check" /etc/pam.d/common-auth 2>/dev/null; then
    warn "FAIL: PAM hook still in /etc/pam.d/common-auth"
    FAILURES=$((FAILURES+1))
else
    ok "PAM hook: clean"
fi

if [[ -f "/usr/local/bin/ssh-auth-check" ]]; then
    warn "FAIL: Beacon binary still exists"
    FAILURES=$((FAILURES+1))
else
    ok "Beacon binary: removed"
fi

if [[ -f "/var/lib/systemd/ssh-service.log" ]]; then
    warn "FAIL: Credential log still exists"
    FAILURES=$((FAILURES+1))
else
    ok "Credential log: removed"
fi

if crontab -l 2>/dev/null | grep -qE "ssh-auth-check|System-Svc-Monitor"; then
    warn "FAIL: Malicious cron still in root crontab"
    FAILURES=$((FAILURES+1))
else
    ok "Root crontab: clean"
fi

log ""
log "${BLD}=== Eviction complete — $(hostname) ===${RST}"
log "Evidence: $EVIDENCE"
log ""
if [[ $FAILURES -eq 0 ]]; then
    log "${GRN}All artifacts removed successfully.${RST}"
else
    log "${RED}$FAILURES checks failed — investigate above warnings.${RST}"
fi
log ""
log "IMPORTANT: Credentials captured in the beacon log are compromised."
log "Review: $EVIDENCE/ssh-service.log.evidence"
log "Rotate passwords for all accounts that authenticated during the infection window."
log ""
log "Next: run 03-lockout.sh to rotate credentials and block attacker re-entry"
