<#
.SYNOPSIS
    Blue Team Tactical Threat Hunt - Reverse Shell Detection
.DESCRIPTION
    Scans active network connections for established sessions tied to suspicious
    processes (cmd, powershell, nc, etc.) or going out over non-standard ports.
    Filters out Overseer traffic to reduce noise.
#>

$OverseerSubnet = "10.10.10."
$StandardPorts = @(80, 443, 25, 53, 3389)
$SuspiciousProcs = @("cmd", "powershell", "pwsh", "nc", "ncat", "netcat", "python", "ruby", "perl", "java", "bash")

Function Write-Log($Message, $Color="White") {
    $Stamp = (Get-Date).ToString("HH:mm:ss")
    Write-Host "[$Stamp] $Message" -ForegroundColor $Color
}

Write-Log "=== Initiating Reverse Shell Sweep ===" "Cyan"
Write-Log "Targeting suspicious outbound connections..." "Cyan"

$ActiveConnections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
$ThreatsFound = 0

foreach ($Conn in $ActiveConnections) {
    if ($Conn.RemoteAddress -like "$OverseerSubnet*") { continue }
    if ($Conn.RemoteAddress -eq "127.0.0.1" -or $Conn.RemoteAddress -eq "::1") { continue }

    $ProcName = "UNKNOWN"
    try {
        $Process = Get-Process -Id $Conn.OwningProcess -ErrorAction SilentlyContinue
        if ($Process) { $ProcName = $Process.ProcessName }
    } catch { }

    $IsSuspicious = $false
    $FlagReason = ""

    foreach ($SusProc in $SuspiciousProcs) {
        if ($ProcName -match $SusProc) {
            $IsSuspicious = $true
            $FlagReason += "[Suspicious Process] "
            break
        }
    }

    if ($Conn.RemotePort -notin $StandardPorts) {
        if ($ProcName -notin @("svchost", "System", "MsMpEng", "explorer")) {
            $IsSuspicious = $true
            $FlagReason += "[Non-Standard Port] "
        }
    }

    if ($IsSuspicious) {
        $ThreatsFound++
        Write-Log "----------------------------------------" "Red"
        Write-Log "WARNING: POTENTIAL REVERSE SHELL DETECTED" "Red"
        Write-Log "Trigger      : $FlagReason" "Yellow"
        Write-Log "Process Name : $ProcName (PID: $($Conn.OwningProcess))" "White"
        Write-Log "Local IP     : $($Conn.LocalAddress):$($Conn.LocalPort)" "White"
        Write-Log "Remote IP    : $($Conn.RemoteAddress):$($Conn.RemotePort)" "Red"

        try {
            $WmiProc = Get-WmiObject Win32_Process -Filter "ProcessId = $($Conn.OwningProcess)" -ErrorAction SilentlyContinue
            if ($WmiProc.CommandLine) {
                Write-Log "Command Line : $($WmiProc.CommandLine)" "DarkGray"
            }
        } catch { }
    }
}

if ($ThreatsFound -eq 0) {
    Write-Log "Sweep complete. No active reverse shells detected." "Green"
} else {
    Write-Log "Sweep complete. Found $ThreatsFound potential threat(s)." "Red"
    Write-Log "Action: Terminate PIDs via 'Stop-Process -Id <PID> -Force' and block Remote IPs at the firewall." "Yellow"
}
Write-Log "=======================================" "Cyan"