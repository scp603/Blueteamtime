# ============================================================
# BASE - Run on ALL Windows machines
# (BLUE-WIN-01..04, SCP-DC-01, SCP-SMB-01, SCP-SMTP-01)
#
# Rule #6:  Must NOT block Grey Team/Overseer access
# Rule #7:  Requires Overseer approval before running
# Rule #12: Must NOT touch Windows Defender Real Time Protection or AV
# ============================================================

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("BLUE-WIN-01","BLUE-WIN-02","BLUE-WIN-03","BLUE-WIN-04",
                 "SCP-DC-01","SCP-SMB-01","SCP-SMTP-01")]
    [string]$ThisMachine
)

# ─── IP Definitions ──────────────────────────────────────────────────────────
$greyTeamRange  = "10.10.10.200-10.10.10.210"   # Overseers + scoring server (.210)

$blueWinRange   = "10.10.10.41-10.10.10.44"     # BLUE-WIN-01..04
$blueLnxRange   = "10.10.10.45-10.10.10.49"     # BLUE-LIN-01..05 — must not be blocked

$winServerIPs   = @("10.10.10.21","10.10.10.22","10.10.10.23")   # DC, SMB, SMTP
$lnxServerIPs   = @("10.10.10.101","10.10.10.102","10.10.10.103","10.10.10.104") # Apache, DB, SSH, VPN

$allTrusted = @($greyTeamRange, $blueWinRange, $blueLnxRange, "100.65.0.0/16") + $winServerIPs + $lnxServerIPs

Write-Host "`n[$(Get-Date -Format 'HH:mm:ss')] Hardening: $ThisMachine" -ForegroundColor Cyan
Write-Host "REMINDER: Confirm Overseer approval (Rule #7) before running." -ForegroundColor Yellow

# ─── Default Profiles ────────────────────────────────────────────────────────
# NOT touching Defender AV or Real Time Protection (Rule #12)
Set-NetFirewallProfile -Profile Domain,Public,Private `
    -DefaultInboundAction Block `
    -DefaultOutboundAction Allow
Write-Host "[+] Default: inbound BLOCK, outbound ALLOW" -ForegroundColor Green

# ─── SSH (22) — all trusted sources ──────────────────────────────────────────
New-NetFirewallRule -DisplayName "Allow SSH Trusted" `
    -Direction Inbound -Protocol TCP -LocalPort 22 `
    -RemoteAddress $allTrusted `
    -Action Allow -ErrorAction SilentlyContinue | Out-Null
Write-Host "[+] SSH (22) opened for trusted ranges" -ForegroundColor Green

# ─── Loopback ────────────────────────────────────────────────────────────────
New-NetFirewallRule -DisplayName "Allow Loopback" `
    -Direction Inbound -RemoteAddress "127.0.0.1" `
    -Action Allow -Protocol Any -ErrorAction SilentlyContinue | Out-Null
Write-Host "[+] Loopback allowed" -ForegroundColor Green

# ─── Grey Team (Rule #6 — REQUIRED) ──────────────────────────────────────────
New-NetFirewallRule -DisplayName "REQUIRED - Allow Grey Team All Inbound" `
    -Direction Inbound -RemoteAddress $greyTeamRange `
    -Action Allow -Protocol Any -ErrorAction SilentlyContinue | Out-Null
Write-Host "[+] Grey Team (.200-.210) allowed inbound — Rule #6" -ForegroundColor Green

# ─── Blue Team Windows Workstations ──────────────────────────────────────────
New-NetFirewallRule -DisplayName "Allow Blue Win Workstations Inbound" `
    -Direction Inbound -RemoteAddress $blueWinRange `
    -Action Allow -Protocol Any -ErrorAction SilentlyContinue | Out-Null
Write-Host "[+] Blue Win workstations (.41-.44) allowed inbound" -ForegroundColor Green

# ─── Blue Team Linux Workstations (must not be blocked) ──────────────────────
New-NetFirewallRule -DisplayName "Allow Blue Linux Workstations Inbound" `
    -Direction Inbound -RemoteAddress $blueLnxRange `
    -Action Allow -Protocol Any -ErrorAction SilentlyContinue | Out-Null
Write-Host "[+] Blue Linux workstations (.45-.49) allowed inbound" -ForegroundColor Green

# ─── All Blue Team Servers ────────────────────────────────────────────────────
New-NetFirewallRule -DisplayName "Allow Win Servers Inbound" `
    -Direction Inbound -RemoteAddress $winServerIPs `
    -Action Allow -Protocol Any -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "Allow Linux Servers Inbound" `
    -Direction Inbound -RemoteAddress $lnxServerIPs `
    -Action Allow -Protocol Any -ErrorAction SilentlyContinue | Out-Null
Write-Host "[+] All Blue Team servers allowed inbound" -ForegroundColor Green

# ─── RDP restricted to trusted range ─────────────────────────────────────────
New-NetFirewallRule -DisplayName "Allow RDP Trusted Only" `
    -Direction Inbound -Protocol TCP -LocalPort 3389 `
    -RemoteAddress $allTrusted `
    -Action Allow -ErrorAction SilentlyContinue | Out-Null
Write-Host "[+] RDP (3389) restricted to trusted ranges" -ForegroundColor Green

# ─── Block dangerous/C2 ports ─────────────────────────────────────────────────
$dangerousPorts = @(21, 23, 4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337)
foreach ($port in $dangerousPorts) {
    New-NetFirewallRule -DisplayName "Block Inbound Port $port" `
        -Direction Inbound -Protocol TCP -LocalPort $port `
        -Action Block -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "[+] Blocked inbound C2/dangerous ports: $($dangerousPorts -join ', ')" -ForegroundColor Green

# ─── Block outbound C2 beaconing ──────────────────────────────────────────────
foreach ($port in @(4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337)) {
    New-NetFirewallRule -DisplayName "Block Outbound Port $port" `
        -Direction Outbound -Protocol TCP -RemotePort $port `
        -Action Block -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "[+] Blocked outbound C2 ports (anti-beaconing)" -ForegroundColor Green

# ─── Per-machine service rules ────────────────────────────────────────────────
switch ($ThisMachine) {

    "SCP-DC-01" {
        # DC scores on ports 389 (LDAP) and 88 (Kerberos) from scoring server (.210)
        # All trusted sources need these for domain auth
        New-NetFirewallRule -DisplayName "DC - Allow LDAP (389) Trusted" `
            -Direction Inbound -Protocol TCP -LocalPort 389 `
            -RemoteAddress $allTrusted -Action Allow -ErrorAction SilentlyContinue | Out-Null
        New-NetFirewallRule -DisplayName "DC - Allow LDAP UDP (389) Trusted" `
            -Direction Inbound -Protocol UDP -LocalPort 389 `
            -RemoteAddress $allTrusted -Action Allow -ErrorAction SilentlyContinue | Out-Null
        New-NetFirewallRule -DisplayName "DC - Allow Kerberos (88) Trusted" `
            -Direction Inbound -Protocol TCP -LocalPort 88 `
            -RemoteAddress $allTrusted -Action Allow -ErrorAction SilentlyContinue | Out-Null
        New-NetFirewallRule -DisplayName "DC - Allow Kerberos UDP (88) Trusted" `
            -Direction Inbound -Protocol UDP -LocalPort 88 `
            -RemoteAddress $allTrusted -Action Allow -ErrorAction SilentlyContinue | Out-Null
        # Additional ports required for AD to function across domain-joined machines
        New-NetFirewallRule -DisplayName "DC - Allow DNS (53)" `
            -Direction Inbound -Protocol TCP -LocalPort 53 `
            -RemoteAddress $allTrusted -Action Allow -ErrorAction SilentlyContinue | Out-Null
        New-NetFirewallRule -DisplayName "DC - Allow DNS UDP (53)" `
            -Direction Inbound -Protocol UDP -LocalPort 53 `
            -RemoteAddress $allTrusted -Action Allow -ErrorAction SilentlyContinue | Out-Null
        New-NetFirewallRule -DisplayName "DC - Allow RPC (135) Trusted" `
            -Direction Inbound -Protocol TCP -LocalPort 135 `
            -RemoteAddress $allTrusted -Action Allow -ErrorAction SilentlyContinue | Out-Null
        New-NetFirewallRule -DisplayName "DC - Allow SMB (445) Trusted" `
            -Direction Inbound -Protocol TCP -LocalPort 445 `
            -RemoteAddress $allTrusted -Action Allow -ErrorAction SilentlyContinue | Out-Null
        New-NetFirewallRule -DisplayName "DC - Allow RPC Dynamic Ports Trusted" `
            -Direction Inbound -Protocol TCP -LocalPort 49152-65535 `
            -RemoteAddress $allTrusted -Action Allow -ErrorAction SilentlyContinue | Out-Null
        Write-Host "[+] SCP-DC-01: LDAP (389), Kerberos (88), DNS (53), RPC (135), SMB (445), RPC dynamic ports opened for trusted" -ForegroundColor Green
    }

    "SCP-SMB-01" {
        # SMB scores on port 445 via AD auth — scoring from .210, team access from trusted
        New-NetFirewallRule -DisplayName "SMB - Allow Port 445 Trusted" `
            -Direction Inbound -Protocol TCP -LocalPort 445 `
            -RemoteAddress $allTrusted -Action Allow -ErrorAction SilentlyContinue | Out-Null
        # NetBIOS ports sometimes needed for legacy SMB discovery
        New-NetFirewallRule -DisplayName "SMB - Allow NetBIOS (137-139) Trusted" `
            -Direction Inbound -Protocol TCP -LocalPort 137,138,139 `
            -RemoteAddress $allTrusted -Action Allow -ErrorAction SilentlyContinue | Out-Null
        New-NetFirewallRule -DisplayName "SMB - Allow NetBIOS UDP (137-138) Trusted" `
            -Direction Inbound -Protocol UDP -LocalPort 137,138 `
            -RemoteAddress $allTrusted -Action Allow -ErrorAction SilentlyContinue | Out-Null
        Write-Host "[+] SCP-SMB-01: SMB (445), NetBIOS (137-139) opened for trusted" -ForegroundColor Green
    }

    "SCP-SMTP-01" {
        # SMTP scores on port 25 — open to trusted; scoring server sends mail from .210
        New-NetFirewallRule -DisplayName "SMTP - Allow Port 25 Trusted" `
            -Direction Inbound -Protocol TCP -LocalPort 25 `
            -RemoteAddress $allTrusted -Action Allow -ErrorAction SilentlyContinue | Out-Null
        Write-Host "[+] SCP-SMTP-01: SMTP (25) opened for trusted" -ForegroundColor Green
    }

    default {
        # BLUE-WIN-01..04 workstations — no additional service ports needed
        Write-Host "[+] $ThisMachine is a workstation — no service-specific rules needed" -ForegroundColor Green
    }
}

Write-Host "`n[$(Get-Date -Format 'HH:mm:ss')] Done. Run 'Get-NetFirewallRule | Where-Object Enabled -eq True | Format-Table DisplayName,Direction,Action' to verify." -ForegroundColor Cyan