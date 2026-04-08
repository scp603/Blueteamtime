<#
.SYNOPSIS
    NTF Initial Hardening Script - Rubric Aligned (Priority 1-3)
.DESCRIPTION
    Automates rapid triage, network containment, and evidence gathering.
    Aligned with Triage Decision Framework (Scenarios 2 & 3).
#>

$IR_Path = "C:\IR"
$LogFile = "$IR_Path\hardening_errors.txt"
$ScriptDir = $PSScriptRoot

Clear-Host
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host " NINE-TAILED FOX: INITIAL HARDENING SCRIPT       " -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

Function Write-Status ($Message, $Color = "Green") { Write-Host "[*] $Message" -ForegroundColor $Color }
Function Log-Error ($Action, $Exception) {
    Write-Host "[!] ERROR during $Action. See log." -ForegroundColor Red
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Action - $($Exception.Message)" | Out-File -FilePath $LogFile -Append
}

# --- PRIORITY 1: ESTABLISH ACCESS & VERIFY SERVICES ---

Try {
    # 1. Establish IR Environment
    If (!(Test-Path $IR_Path)) { New-Item -ItemType Directory -Path $IR_Path -Force | Out-Null }
    If (!(Test-Path "$IR_Path\autorunsc.exe")) {
        If (Test-Path "$ScriptDir\sysinternals_tools.zip") {
            Expand-Archive -Path "$ScriptDir\sysinternals_tools.zip" -DestinationPath $IR_Path -Force
            Write-Status "Extracted Sysinternals Tools to $IR_Path" "Yellow"
        } Else { Write-Host "[!] Warning: sysinternals_tools.zip not found." -ForegroundColor Red }
    }

    # 2. Verify Scored Services (Rubric Priority 1)
    $CriticalServices = @("NTDS", "DNS", "Netlogon")
    Foreach ($Service in $CriticalServices) {
        $SvcStatus = Get-Service -Name $Service -ErrorAction SilentlyContinue
        If ($null -eq $SvcStatus) { Continue }
        If ($SvcStatus.Status -ne "Running") {
            Start-Service -Name $Service -ErrorAction Stop
            Write-Status "Priority 1: Service $Service was down and has been restarted." "Yellow"
        } Else { Write-Status "Priority 1: Service $Service is Running." }
    }
} Catch { Log-Error "Priority 1 Tasks" $_ }

# --- PRIORITY 2: URGENT CONTAINMENT & HARDENING ---

Try {
    # 3. Audit Domain Admins (Scenario 3 Compliance)
    net group "Domain Admins" /domain > "$IR_Path\DA_Audit.txt" 2>$null
    Write-Status "Priority 2: Domain Admins dumped to $IR_Path\DA_Audit.txt for review." "Yellow"

    # 4. Defender Compliance & Firewall Enforcement
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop
    Write-Status "Priority 2: Real-Time AV Disabled. Defender Firewall ENABLED." "Yellow"

    # 5. Automated Port Hardening (Block C2)
    $RuleName = "NTF_Block_C2"
    If (!(Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Action Block -Protocol TCP -LocalPort 4444,8080,1337,44444 -ErrorAction Stop | Out-Null
        Write-Status "Priority 2: C2 Port blocking rule established." "Yellow"
    } Else { Write-Status "Priority 2: C2 Port blocking rule active." }

    # 6. SMB Hardening
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -RequireSecuritySignature $true -Force -ErrorAction Stop
    Write-Status "Priority 2: SMBv1 Disabled and SMB Signing Required." "Yellow"

# 7. Persistence Hunt (Autoruns) - Timestamped for continuous hunting
    If (Test-Path "$IR_Path\autorunsc.exe") {
        # Define and create the dedicated subfolder
        $PersistFolder = "$IR_Path\Persistence_Logs"
        If (!(Test-Path $PersistFolder)) { 
            New-Item -ItemType Directory -Path $PersistFolder -Force | Out-Null 
        }

        Write-Status "Priority 2: Running Autoruns... this may take a few seconds." "Yellow"
        
        # Grab the current time (e.g., 1435 for 2:35 PM)
        $TimeMap = Get-Date -Format "HHmm"
        $PersistFile = "$PersistFolder\persistence_$TimeMap.csv"
        
        # Run autoruns and pipe to the uniquely named file in the new folder
        Start-Process -FilePath "$IR_Path\autorunsc.exe" -ArgumentList "-a * -c -m -accepteula" -RedirectStandardOutput $PersistFile -Wait
        
        Write-Status "Priority 2: Persistence CSV generated at $PersistFile" "Yellow"
    }
} Catch { Log-Error "Priority 2 Tasks" $_ }

# --- PRIORITY 3: MONITORING & LOGGING ---

Try {
    # 8. Start Packet Capture
    If ((pktmon status) -match "Running") {
        Write-Status "Priority 3: Pktmon is already actively capturing traffic."
    } Else {
        pktmon filter add -p 4444 8080 1337 | Out-Null
        pktmon start --etw -f $IR_Path\capture.etl | Out-Null
        Write-Status "Priority 3: Packet capture initiated at $IR_Path\capture.etl" "Yellow"
    }
} Catch { Log-Error "Priority 3 Tasks" $_ }

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host " HARDENING COMPLETE. BEGIN HUMAN ANALYSIS.       " -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan
