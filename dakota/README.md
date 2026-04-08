**Author:** Dakota Fedor  
**Target Systems:** SCP-SMTP-01 (Windows Server 2019), BLUE-WIN-01 through 04 (Windows 11)

## Overview
This repository contains PowerShell automation scripts designed for the initial 5-minute triage phase. These scripts establish baseline security, configure Windows Firewall rules, and enable advanced audit logging while maintaining required scoring engine uptime (Rule 6 and Rule 8 compliance).

## Execution Prerequisites
All scripts require administrative privileges and an unrestricted execution policy.

Open an elevated PowerShell session (Run as Administrator) and execute the following command before running any of the scripts below:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
```

---

## Scripts & Usage

The hardening scripts use an idempotent design and include `-Action Apply` and `-Action Revert` parameters. This allows for immediate rollback if a configuration breaks a required service dependency.

### 1. Harden-SMTP.ps1
**Target:** `SCP-SMTP-01`  
**Description:** Secures the SMTP server by enabling advanced process logging, disabling the Telnet service, and restricting RDP access strictly to the scoring subnet (`10.10.10.200/24`). It explicitly allows inbound traffic on Port 25 from all sources to ensure scoring continuity.

* **To Apply Hardening:**
  ```powershell
  .\Harden-SMTP.ps1 -Action Apply
  ```
* **To Revert Changes:**
  ```powershell
  .\Harden-SMTP.ps1 -Action Revert
  ```

### 2. Harden-Endpoints.ps1
**Target:** `BLUE-WIN-01` to `BLUE-WIN-04`  
**Description:** Hardens Windows 11 workstations to prevent lateral movement. It disables LLMNR, enforces SMB signing, disables unnecessary services (Print Spooler, Telnet), and blocks inbound SMB, RDP, and Telnet traffic from outside the authorized scoring subnet.

* **To Apply Hardening:**
  ```powershell
  .\Harden-Endpoints.ps1 -Action Apply
  ```
* **To Revert Changes:**
  ```powershell
  .\Harden-Endpoints.ps1 -Action Revert
  ```

### 3. Hunt-ReverseShells.ps1
**Target:** All Windows Systems  
**Description:** A monitoring script that scans for established TCP connections tied to suspicious processes (e.g., `cmd`, `powershell`, `nc`) or non-standard ports. It automatically filters out the `10.10.10.200/24` subnet to prevent flagging legitimate scoring traffic. If a threat is found, it extracts the command-line arguments used to launch the process.

* **To Run the Scan:**
  ```powershell
  .\Hunt-ReverseShells.ps1
  ```
  *(Note: Run this continuously or at regular intervals after the initial 5-minute lockdown).*

---

## Telemetry & Logging
The scripts implement local logging for troubleshooting and threat hunting:

* **Execution Logs:** Script actions (applied rules, disabled services, errors) are recorded locally at `C:\BlueTeam_SMTP_Harden.log` and `C:\BlueTeam_Endpoint_Harden.log`.
* **Event Viewer Logs:** The hardening scripts configure `auditpol` to capture Process Creation (Event ID 4688, including full command-line arguments via registry modification) and Logon events (Event IDs 4624/4625) in the Windows Security log.