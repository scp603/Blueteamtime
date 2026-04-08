<#
.SYNOPSIS
    Blue Team First 5 Min - SCP-SMTP-01 Server Hardening
.DESCRIPTION
    Configures advanced logging and strict firewall rules for the mail server.
    Ensures Port 25 is open for scoring (10.10.10.200-210), locks RDP/WinRM, and completely disables Telnet.
#>

param (
    [ValidateSet("Apply", "Revert")]
    [string]$Action = "Apply"
)

$OverseerSubnet = "10.10.10.200/24"
$LogPath = "C:\BlueTeam_SMTP_Harden.log"

Function Write-Log($Message) {
    $Stamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $Line = "[$Stamp] [SMTP] $Message"
    Write-Host $Line -ForegroundColor Yellow
    Add-Content -Path $LogPath -Value $Line
}

Write-Log "=== SMTP Hardening Script Initiated: $Action ==="

if ($Action -eq "Apply") {
    # 1. LOGGING SETUP
    Write-Log "Enabling Advanced Audit Logging..."
    try {
        auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
        auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Force
        Write-Log " [+] Audit logging enabled."
    } catch { Write-Log " [!] Failed to set auditpol." }

    # 2. FIREWALL: OVERSEER CORE RULE
    Write-Log "Setting Overseer Whitelist..."
    if (-not (Get-NetFirewallRule -DisplayName "NTF-OVERSEERS-ALLOW" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "NTF-OVERSEERS-ALLOW" -Direction Inbound -RemoteAddress $OverseerSubnet -Action Allow -Profile Any | Out-Null
        Write-Log " [+] Overseer subnet ($OverseerSubnet) explicitly allowed."
    }

    # 3. FIREWALL: SECURE SMTP (PORT 25)
    Write-Log "Securing Port 25..."
    if (-not (Get-NetFirewallRule -DisplayName "NTF-SMTP-SCORING" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "NTF-SMTP-SCORING" -Direction Inbound -LocalPort 25 -Protocol TCP -Action Allow | Out-Null
        Write-Log " [+] Port 25 explicitly allowed for scoring."
    }

    # 4. FIREWALL: RESTRICT MANAGEMENT (RDP & SSH)
    Write-Log "Restricting RDP and SSH to Overseers Only..."
    if (-not (Get-NetFirewallRule -DisplayName "NTF-BLOCK-RDP" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "NTF-ALLOW-RDP-OVERSEERS" -Direction Inbound -LocalPort 3389 -Protocol TCP -RemoteAddress $OverseerSubnet -Action Allow | Out-Null
        New-NetFirewallRule -DisplayName "NTF-BLOCK-RDP" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Block | Out-Null
        New-NetFirewallRule -DisplayName "NTF-ALLOW-SSH-OVERSEERS" -Direction Inbound -LocalPort 22 -Protocol TCP -RemoteAddress $OverseerSubnet -Action Allow | Out-Null
        New-NetFirewallRule -DisplayName "NTF-BLOCK-SSH" -Direction Inbound -LocalPort 22 -Protocol TCP -Action Block | Out-Null
        Write-Log " [+] RDP and SSH locked down."
    }

    # 5. SERVICE & PROTOCOL: KILL TELNET
    Write-Log "Neutralizing Telnet..."
    Stop-Service -Name "TlntSvr" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "TlntSvr" -StartupType Disabled -ErrorAction SilentlyContinue
    if (-not (Get-NetFirewallRule -DisplayName "NTF-BLOCK-TELNET" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "NTF-BLOCK-TELNET" -Direction Inbound -LocalPort 23 -Protocol TCP -Action Block | Out-Null
    }
    Write-Log " [+] Telnet service disabled and Port 23 blocked."

    Write-Log "=== SMTP Application Complete ==="
}
elseif ($Action -eq "Revert") {
    Write-Log "Reverting changes..."

    auditpol /set /subcategory:"Process Creation" /success:disable /failure:disable | Out-Null
    auditpol /set /subcategory:"Logon" /success:disable /failure:disable | Out-Null
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 0 -Force

    $Rules = @("NTF-OVERSEERS-ALLOW", "NTF-SMTP-SCORING", "NTF-ALLOW-RDP-OVERSEERS", "NTF-BLOCK-RDP", "NTF-ALLOW-SSH-OVERSEERS", "NTF-BLOCK-SSH", "NTF-BLOCK-TELNET")
    foreach ($Rule in $Rules) {
        Remove-NetFirewallRule -DisplayName $Rule -ErrorAction SilentlyContinue
    }

    try {
        Set-Service -Name "TlntSvr" -StartupType Manual -ErrorAction SilentlyContinue
        Start-Service -Name "TlntSvr" -ErrorAction SilentlyContinue
        Write-Log " [+] Restored and started TlntSvr (Telnet)."
    } catch { Write-Log " [!] Failed to restore Telnet." }

    Write-Log " [+] Reversion complete. Firewall, services, and logging reset to baseline."
}