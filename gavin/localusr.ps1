param(
    [switch]$t
)

function Confirm-Password([SecureString] $securePassword, $storedSaltedHash) {
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    try {
        $plaintext = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)

        $lastDollar = $storedSaltedHash.LastIndexOf('$')
        $salt       = $storedSaltedHash.Substring(0, $lastDollar)
        $storedHash = $storedSaltedHash.Substring($lastDollar + 1)

        $combined  = $salt + $plaintext
        $hashBytes = [System.Security.Cryptography.SHA256]::Create().ComputeHash(
            [System.Text.Encoding]::UTF8.GetBytes($combined)
        )
        $computedHash = [BitConverter]::ToString($hashBytes) -replace '-'
        return $computedHash -eq $storedHash
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

if ($t) {
    $url = "http://127.0.0.1:8080/passwords.json"
} else {
    $url = "https://raw.githubusercontent.com/gavcs/Blueteamtime-passholder/main/passwords.json"
}

$raw       = Invoke-WebRequest -Uri $url
$encrypted = $raw.Content | ConvertFrom-Json

# Pull cyberrange entry specifically
$cyberrangeEntry = $encrypted.PSObject.Properties | Where-Object { $_.Name -eq "cyberrange" }
if (-not $cyberrangeEntry) {
    Write-Host "ERROR: cyberrange not found in passwords.json" -ForegroundColor Red
    exit 1
}

$keyInput = Read-Host -AsSecureString "Enter key"
$keyPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($keyInput)
)
$keyBytes = [System.Text.Encoding]::UTF8.GetBytes($keyPlain.PadRight(32).Substring(0, 32))

$securePassword = $cyberrangeEntry.Value.encrypted | ConvertTo-SecureString -Key $keyBytes

if (-not (Confirm-Password $securePassword $cyberrangeEntry.Value.hash)) {
    Write-Host "VERIFICATION FAILED for cyberrange — aborting!" -ForegroundColor Red
    exit 1
}
if (!$t) {
    Set-LocalUser -Name "cyberrange" -Password $securePassword
    Write-Host "Password changed for local cyberrange" -ForegroundColor Green
}