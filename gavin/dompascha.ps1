function Confirm-Password($securePassword, $storedSaltedHash) {
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

# $url = "https://github.com/scp603/Blueteamtime/blob/main/gavin/passwords.json"
$url = "http://127.0.0.1:8080/gavin/passwords.json"
$raw = Invoke-WebRequest -Uri $url
$encrypted = $raw.Content | ConvertFrom-Json

# TODO: check if each user is part of hard coded list of users here

$keyInput = Read-Host -AsSecureString "Enter key"
$keyPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($keyInput)
)
$keyBytes = [System.Text.Encoding]::UTF8.GetBytes($keyPlain.PadRight(32).Substring(0,32))

foreach ($user in $encrypted.PSObject.Properties) {
    $securePassword = $user.Value.encrypted | ConvertTo-SecureString -Key $keyBytes

    # Verify before applying
    $plaintext = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    )
    Write-Host "DEBUG $($user.Name) : $plaintext"

    if (-not (Confirm-Password $securePassword $user.Value.hash)) {
        Write-Host "VERIFICATION FAILED for $($user.Name) — skipping!" -ForegroundColor Red
        continue
    }

    # Set-ADAccountPassword -Identity $user.Name `
    #     -NewPassword $securePassword `
    #     -Reset
    # Write-Host "Password changed for $($user.Name)" -ForegroundColor Green
}