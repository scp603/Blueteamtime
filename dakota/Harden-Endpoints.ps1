<#
.SYNOPSIS
    Blue Team Endpoint Hardening - Windows 11 Workstations
.DESCRIPTION
    Aggressive endpoint lock-down. Kills vulnerable services (Spooler, Telnet),
    disables LLMNR, hardens SMB, and restricts inbound connections.
#>

param (
    [ValidateSet("Apply", "Revert")]
    [string]$Action = "Apply"
)

$OverseerSubnet = "10.10.10.200/24"
$LogPath = "C:\BlueTeam_Endpoint_Harden.log"

Function Write-Log($Message) {
    $Stamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $Line = "[$Stamp] [ENDPOINT] $Message"
    Write-Host $Line -ForegroundColor Cyan
    Add-Content -Path $LogPath -Value $Line
}

Write-Log "=== Endpoint Hardening Script Initiated: $Action ==="

if ($Action -eq "Apply") {

    # 1. SERVICE HARDENING (Reduce Attack Surface)
    Write-Log "Disabling vulnerable/unnecessary services..."
    $ServicesToKill = @("Spooler", "XboxGipSvc", "XblAuthManager", "XblGameSave", "XboxNetApiSvc", "bthserv", "TlntSvr")
    foreach ($Svc in $ServicesToKill) {
        try {
            Stop-Service -Name $Svc -Force -ErrorAction SilentlyContinue
            Set-Service -Name $Svc -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Log " [+] Disabled $Svc"
        } catch { }
    }

    # 2. PROTOCOL HARDENING
    Write-Log "Disabling LLMNR (Mitigate Responder attacks)..."
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Force

    Write-Log "Enabling SMB Signing..."
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1 -Force

    # 3. FIREWALL: ISOLATE WORKSTATION
    Write-Log "Applying strict endpoint firewall rules..."
    New-NetFirewallRule -DisplayName "NTF-OVERSEERS-ALLOW" -Direction Inbound -RemoteAddress $OverseerSubnet -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null

    # Block inbound SMB, RDP, and Telnet to prevent lateral movement
    New-NetFirewallRule -DisplayName "NTF-BLOCK-INBOUND-SMB" -Direction Inbound -LocalPort 445 -Protocol TCP -Action Block -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "NTF-BLOCK-INBOUND-RDP" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Block -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "NTF-BLOCK-INBOUND-TELNET" -Direction Inbound -LocalPort 23 -Protocol TCP -Action Block -ErrorAction SilentlyContinue | Out-Null

    # 4. LOGGING
    Write-Log "Enabling advanced process logging..."
    auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null

    Write-Log "=== Endpoint Application Complete ==="
}
elseif ($Action -eq "Revert") {
    Write-Log "Reverting endpoint hardening..."

    $ServicesToRestore = @("Spooler")
    foreach ($Svc in $ServicesToRestore) {
        Set-Service -Name $Svc -StartupType Manual -ErrorAction SilentlyContinue
    }

    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 0 -Force

    $Rules = @("NTF-OVERSEERS-ALLOW", "NTF-BLOCK-INBOUND-SMB", "NTF-BLOCK-INBOUND-RDP", "NTF-BLOCK-INBOUND-TELNET")
    foreach ($Rule in $Rules) {
        Remove-NetFirewallRule -DisplayName $Rule -ErrorAction SilentlyContinue
    }

    auditpol /clear /y | Out-Null
    Write-Log " [+] Endpoint reversion complete."
}