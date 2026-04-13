# Windows Hardening Script — CDT Competition 3
# Run as Administrator on each machine (locally on workstations, or push via DC for servers)
#
# RULE 12 COMPLIANCE: This script does NOT touch Windows Defender Real Time
# Protection or Antivirus in any way. No Set-MpPreference calls are made.
#
# RULE 6 COMPLIANCE: Grey team access is never blocked or restricted.
# RULE 2 COMPLIANCE: Grey team users are never modified.
# USER POLICY: No users are deleted — only disabled where permitted.

Write-Host "`n=== CDT Hardening Script ===" -ForegroundColor Cyan
Write-Host "NOTE: Windows Defender AV/RTP is intentionally not touched (Rule 12)" -ForegroundColor Yellow

# ─── Detect machine role ──────────────────────────────────────────────────────
$isDC = (Get-WindowsFeature -Name AD-Domain-Services -ErrorAction SilentlyContinue).InstallState -eq "Installed"
Write-Host "`nDetected as $(if ($isDC) { 'Domain Controller' } else { 'Member Server / Workstation' })" -ForegroundColor Cyan


# ════════════════════════════════════════════════════════════════════════════════
# 1. PASSWORD & ACCOUNT LOCKOUT POLICY
#    Matches the competition's documented security policy (12 char min, complexity,
#    90-day expiry)
# ════════════════════════════════════════════════════════════════════════════════
Write-Host "`n[1] Applying password and lockout policy..." -ForegroundColor Cyan

if ($isDC) {
    # On the DC, set domain-wide policy via Fine-Grained or Default Domain Policy
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue

    $domain = Get-ADDomain
    Set-ADDefaultDomainPasswordPolicy -Identity $domain `
        -MinPasswordLength 12 `
        -PasswordHistoryCount 10 `
        -MaxPasswordAge (New-TimeSpan -Days 90) `
        -MinPasswordAge (New-TimeSpan -Days 1) `
        -ComplexityEnabled $true `
        -ReversibleEncryptionEnabled $false `
        -LockoutThreshold 5 `
        -LockoutDuration (New-TimeSpan -Minutes 15) `
        -LockoutObservationWindow (New-TimeSpan -Minutes 15)

    Write-Host "  Domain password policy applied." -ForegroundColor Green
} else {
    # On non-DC machines, set local policy via secedit
    $secCfg = @"
[System Access]
MinimumPasswordLength = 12
PasswordComplexity = 1
PasswordHistorySize = 10
MaximumPasswordAge = 90
MinimumPasswordAge = 1
LockoutBadCount = 5
ResetLockoutCount = 15
LockoutDuration = 15
"@
    $tmpCfg = "$env:TEMP\secpol.cfg"
    $tmpDb  = "$env:TEMP\secpol.sdb"
    $secCfg | Out-File -FilePath $tmpCfg -Encoding ASCII
    secedit /configure /db $tmpDb /cfg $tmpCfg /quiet
    Remove-Item $tmpCfg, $tmpDb -ErrorAction SilentlyContinue
    Write-Host "  Local password policy applied." -ForegroundColor Green
}


# ════════════════════════════════════════════════════════════════════════════════
# 2. DISABLE THE CYBERRANGE ACCOUNT
#    Permitted by the blue team packet ("YOU MAY DISABLE CYBERRANGE")
# ════════════════════════════════════════════════════════════════════════════════
# Write-Host "`n[2] Disabling cyberrange account..." -ForegroundColor Cyan

# if ($isDC) {
#     Disable-ADAccount -Identity "cyberrange" -ErrorAction SilentlyContinue
#     Write-Host "  AD cyberrange account disabled." -ForegroundColor Green
# } else {
#     Disable-LocalUser -Name "cyberrange" -ErrorAction SilentlyContinue
#     Write-Host "  Local cyberrange account disabled." -ForegroundColor Green
# }


# ════════════════════════════════════════════════════════════════════════════════
# 3. DISABLE SMBV1
#    SMBv1 is exploitable (EternalBlue, WannaCry). SMBv2/3 are unaffected.
# ════════════════════════════════════════════════════════════════════════════════
# Write-Host "`n[3] Disabling SMBv1..." -ForegroundColor Cyan

# Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
# Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
#     -Name SMB1 -Type DWORD -Value 0 -ErrorAction SilentlyContinue

# Write-Host "  SMBv1 disabled." -ForegroundColor Green


# ════════════════════════════════════════════════════════════════════════════════
# 4. DISABLE LLMNR AND NETBIOS OVER TCP/IP
#    Prevents LLMNR/NBT-NS poisoning attacks (Responder)
# ════════════════════════════════════════════════════════════════════════════════
Write-Host "`n[4] Disabling LLMNR and NetBIOS over TCP/IP..." -ForegroundColor Cyan

# Disable LLMNR via registry
$llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
If (-not (Test-Path $llmnrPath)) { New-Item -Path $llmnrPath -Force | Out-Null }
Set-ItemProperty -Path $llmnrPath -Name EnableMulticast -Type DWORD -Value 0

# Disable NetBIOS over TCP/IP on all adapters
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
foreach ($adapter in $adapters) {
    # 2 = Disable NetBIOS over TCP/IP
    $adapter.SetTcpipNetbios(2) | Out-Null
}

Write-Host "  LLMNR and NetBIOS disabled." -ForegroundColor Green


# ════════════════════════════════════════════════════════════════════════════════
# 5. DISABLE WEAK TLS/SSL PROTOCOLS
#    Disables SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1. Keeps TLS 1.2 and 1.3.
# ════════════════════════════════════════════════════════════════════════════════
Write-Host "`n[5] Disabling weak TLS/SSL protocols..." -ForegroundColor Cyan

$weakProtocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
foreach ($proto in $weakProtocols) {
    $serverPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Server"
    $clientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Client"

    foreach ($path in @($serverPath, $clientPath)) {
        If (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name Enabled       -Type DWORD -Value 0
        Set-ItemProperty -Path $path -Name DisabledByDefault -Type DWORD -Value 1
    }
}

Write-Host "  Weak protocols disabled." -ForegroundColor Green


# ════════════════════════════════════════════════════════════════════════════════
# 6. RESTRICT NTLM
#    Forces NTLMv2 only — prevents downgrade to NTLMv1 which is trivially cracked
# ════════════════════════════════════════════════════════════════════════════════
Write-Host "`n[6] Restricting NTLM to v2 only..." -ForegroundColor Cyan

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name LmCompatibilityLevel -Type DWORD -Value 5
# 5 = Send NTLMv2 only, refuse LM and NTLMv1

Write-Host "  NTLMv2 enforced." -ForegroundColor Green


# ════════════════════════════════════════════════════════════════════════════════
# 7. DISABLE UNNECESSARY / DANGEROUS SERVICES
#    Telnet and FTP are plaintext and have no role in this competition.
#    Print Spooler has known RCE exploits (PrintNightmare) and is not needed.
#    WinRM is kept enabled — needed for remote management from the DC.
# ════════════════════════════════════════════════════════════════════════════════
Write-Host "`n[7] Disabling unnecessary services..." -ForegroundColor Cyan

$servicesToDisable = @(
    "TlntSvr",   # Telnet
    "ftpsvc",    # FTP (IIS FTP)
    "Spooler"    # Print Spooler (PrintNightmare)
)

foreach ($svc in $servicesToDisable) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service) {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service  -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Host "  Disabled: $svc" -ForegroundColor Green
    } else {
        Write-Host "  Not found (skipping): $svc" -ForegroundColor DarkGray
    }
}


# ════════════════════════════════════════════════════════════════════════════════
# 8. SECURE RDP
#    Requires Network Level Authentication (NLA) — credentials verified before
#    session is established, reduces attack surface significantly.
# ════════════════════════════════════════════════════════════════════════════════
Write-Host "`n[8] Securing RDP (enforcing NLA)..." -ForegroundColor Cyan

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name UserAuthentication -Type DWORD -Value 1

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name SecurityLayer -Type DWORD -Value 2
# SecurityLayer 2 = SSL/TLS required

Write-Host "  RDP NLA enforced." -ForegroundColor Green


# ════════════════════════════════════════════════════════════════════════════════
# 9. DISABLE NULL SESSIONS AND ANONYMOUS ACCESS
#    Prevents unauthenticated enumeration of shares, users, and groups.
# ════════════════════════════════════════════════════════════════════════════════
Write-Host "`n[9] Restricting anonymous/null session access..." -ForegroundColor Cyan

$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $lsaPath -Name RestrictAnonymous      -Type DWORD -Value 1
Set-ItemProperty -Path $lsaPath -Name RestrictAnonymousSAM   -Type DWORD -Value 1
Set-ItemProperty -Path $lsaPath -Name EveryoneIncludesAnonymous -Type DWORD -Value 0

Write-Host "  Null sessions restricted." -ForegroundColor Green


# ════════════════════════════════════════════════════════════════════════════════
# 10. ENABLE AUDIT POLICIES
#     Required by the competition's compliance policy ("Log all events").
#     Covers logon, account management, object access, privilege use, and process
#     tracking — all useful for the incident detection log.
# ════════════════════════════════════════════════════════════════════════════════
Write-Host "`n[10] Enabling audit policies..." -ForegroundColor Cyan

$auditCategories = @(
    "Logon/Logoff",
    "Account Logon",
    "Account Management",
    "Object Access",
    "Privilege Use",
    "Process Tracking",
    "Policy Change",
    "System"
)

foreach ($cat in $auditCategories) {
    auditpol /set /category:"$cat" /success:enable /failure:enable | Out-Null
}

Write-Host "  Audit policies enabled." -ForegroundColor Green


# ════════════════════════════════════════════════════════════════════════════════
# 11. INCREASE EVENT LOG SIZES
#     Default log sizes fill up quickly under active attack. Ensures you keep
#     enough history for the incident detection log and post-breach debriefing.
# ════════════════════════════════════════════════════════════════════════════════
Write-Host "`n[11] Increasing event log sizes..." -ForegroundColor Cyan

$logs = @("Security", "System", "Application")
foreach ($log in $logs) {
    $logConfig = Get-WinEvent -ListLog $log -ErrorAction SilentlyContinue
    if ($logConfig) {
        $logConfig.MaximumSizeInBytes = 196608000  # 200 MB
        $logConfig.SaveChanges()
        Write-Host "  $log log set to 200MB." -ForegroundColor Green
    }
}


# ════════════════════════════════════════════════════════════════════════════════
# 12. DISABLE AUTORUN / AUTOPLAY
#     Prevents malicious USB payloads from auto-executing.
# ════════════════════════════════════════════════════════════════════════════════
Write-Host "`n[12] Disabling AutoRun/AutoPlay..." -ForegroundColor Cyan

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -Name NoDriveTypeAutoRun -Type DWORD -Value 255 -ErrorAction SilentlyContinue

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
    -Name NoAutoplayfornonVolume -Type DWORD -Value 1 -ErrorAction SilentlyContinue

Write-Host "  AutoRun/AutoPlay disabled." -ForegroundColor Green


# ════════════════════════════════════════════════════════════════════════════════
# 13. POWERSHELL SCRIPT BLOCK LOGGING
#     Logs all PowerShell script content to the event log — critical for catching
#     attacker activity and fulfilling the incident detection log requirements.
# ════════════════════════════════════════════════════════════════════════════════
Write-Host "`n[13] Enabling PowerShell script block logging..." -ForegroundColor Cyan

$psLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
If (-not (Test-Path $psLogPath)) { New-Item -Path $psLogPath -Force | Out-Null }
Set-ItemProperty -Path $psLogPath -Name EnableScriptBlockLogging -Type DWORD -Value 1

Write-Host "  PowerShell script block logging enabled." -ForegroundColor Green


# ════════════════════════════════════════════════════════════════════════════════
# DONE
# ════════════════════════════════════════════════════════════════════════════════
Write-Host "`n=== Hardening complete. A reboot may be required for some changes to take effect. ===" -ForegroundColor Cyan
Write-Host "Reminder: Windows Defender AV/RTP was NOT touched (Rule 12 compliant)." -ForegroundColor Yellow