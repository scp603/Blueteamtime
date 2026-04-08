# README: Initial Hardening Script Execution Guide

**Overview:**
`InitialHardening.ps1` is designed to be executed locally on the Windows Server 2022 DC during the first 5 minutes of the competition. It leverages pre-installed `git` to pull critical IR tools and scripts directly from this repository, establishing strict Defender firewall rules, and capturing network traffic.

### 1. Pre-Competition Preparation (GitHub Setup)
Ensure your GitHub repository is structured with the following two files at the root level:
1. `InitialHardening.ps1`
2. `sysinternals_tools.zip`

### 2. Execution Steps (First 5 Minutes)
1. **Launch PowerShell as Administrator:** Click the Start menu, type `powershell`, right-click **Windows PowerShell**, and select **Run as Administrator**.
2. **Execute the Deployment:** Run the following commands to clone your repository and execute the hardening script immediately. *(Replace the URL with your actual repository link)*:

```powershell
# 1. Clone the repository directly to the root of C:\
git clone https://github.com/jnl1479/BlueTeamDC.git C:\NTF_Defense

# 2. Navigate into the cloned directory
cd C:\NTF_Defense

# 3. Execute the script with bypassed execution policy
powershell.exe -ExecutionPolicy Bypass -File .\InitialHardening.ps1
```

### 3. Expected Output & Verification
The script is designed to provide immediate visual feedback. Do not close the window until you see the cyan "HARDENING COMPLETE" banner.

* 🟢 **Green Output (`[*]`)**: The configuration was checked and is already secure/compliant.
* 🟡 **Yellow Output (`[*]`)**: A change was successfully made (e.g., a rule was created, a service was restarted).
* 🔴 **Red Output (`[!]`)**: An error occurred. The script will log the error to `C:\IR\hardening_errors.txt` and continue to the next task.

### 4. Post-Execution Triage
Once the script finishes:
1. Open File Explorer and navigate to `C:\IR`.
2. Open `persistence.csv` to identify backdoor registry keys or scheduled tasks established by the Red Team.
  `Import-Csv C:\IR\Persistence_Logs\persistence_1435.csv | Out-GridView`
3. Launch `procexp.exe` to begin manually hunting for malicious processes hiding as legitimate Windows services.
