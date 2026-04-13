param(
    [switch]$t
)
function Confirm-Password([SecureString] $securePassword, $storedSaltedHash) {
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    try {
        $plaintext = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)

        # Use LastIndexOf to avoid splitting on $ inside the salt
        $lastDollar = $storedSaltedHash.LastIndexOf('$')
        $salt       = $storedSaltedHash.Substring(0, $lastDollar)
        $storedHash = $storedSaltedHash.Substring($lastDollar + 1)

        $combined = $salt + $plaintext
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

# Rest of the script continues as normal...
$raw = Invoke-WebRequest -Uri $url
$encrypted = $raw.Content | ConvertFrom-Json

$keyInput = Read-Host -AsSecureString "Enter key"
$keyPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($keyInput)
)
$keyBytes = [System.Text.Encoding]::UTF8.GetBytes($keyPlain.PadRight(32).Substring(0,32))

foreach ($user in $encrypted.PSObject.Properties) {
    $securePassword = $user.Value.encrypted | ConvertTo-SecureString -Key $keyBytes

    if ($t) {
        $plaintext = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
        )
        Write-Host "[DEBUG] $($user.Name) : $plaintext"
        if (-not (Confirm-Password $securePassword $user.Value.hash)) {
            Write-Host "VERIFICATION FAILED for $($user.Name) — skipping!" -ForegroundColor Red
            continue
        }
    } else {
        if ($($user.Name) -ne "USE THIS PASSWORD FOR ANY OTHER USER NOT LISTED IN THE PACKET", "cyberrange") {
            Set-ADAccountPassword -Identity $user.Name `
                -NewPassword $securePassword `
                -Reset
            Write-Host "Password changed for $($user.Name)" -ForegroundColor Green
        }
    }
}


# PT 2 electric boogaloo disabling unnamed users
if (!$t) {
    $notouch = @("cyberrange", "GREYTEAM", "GRAYTEAM", "SQL_APACHE_GREYTEAM", "SQL_APACHE_GRAYTEAM",
                "SCORER_GREYTEAM", "SCORER_GRAYTEAM", "GREY_ADMIN", "GRAY_ADMIN", "SCP073", "SCP343",
                "krbtgt")

    Write-Host "`nDisabling unlisted domain users..." -ForegroundColor Cyan

    Get-ADUser -Filter * | ForEach-Object {
        $username = $_.SamAccountName

        if ($username -in $notouch) { return }
        if ($username -in $listedUsers) { return }

        Disable-ADAccount -Identity $username
        Write-Host "Disabled $username" -ForegroundColor Yellow
    }
}