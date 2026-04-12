$key = Read-Host -AsSecureString "FoxtrotTeamKeyForBlueTeam26cday1"
$keyPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($key)
)
$keyBytes = [System.Text.Encoding]::UTF8.GetBytes($keyPlain.PadRight(32).Substring(0,32))

$chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*'
function getPass {
    return -join ((1..10) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
}
function Get-SaltedHash($plaintext) {
    $salt = -join ((1..16) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    $combined = $salt + $plaintext
    $hashBytes = [System.Security.Cryptography.SHA256]::Create().ComputeHash(
        [System.Text.Encoding]::UTF8.GetBytes($combined)
    )
    $hash = [BitConverter]::ToString($hashBytes) -replace '-'
    return "$salt`$$hash"   # stored as salt$hash
}

$users = @("Rick Thompson", "Odongo Tejani", "Theodore Blackwood", "Daniel Asheworth", "Simon Glass", "USE THIS PASSWORD FOR ANY OTHER USER NOT LISTED IN THE PACKET")
$output = @{}
Write-Host "`nUser : Salted+Hashed Password" -ForegroundColor Cyan
Write-Host "------------------------------" -ForegroundColor Cyan
foreach ($user in $users) {
    $plainPassword = getPass
    
    $secureStr = ConvertTo-SecureString $plainPassword -AsPlainText -Force
    $encryptedStr = ConvertFrom-SecureString $secureStr -Key $keyBytes
    $saltedHash = Get-SaltedHash $plainPassword

    # Store both together per user
    $output[$user] = @{
        encrypted = $encryptedStr
        hash      = $saltedHash
    }

    Write-Host "SaltedHashed: $user : $saltedHash"
    Write-Host "Plaintext: $user : $plainPassword"
}

[PSCustomObject]$output | ConvertTo-Json -Depth 3 | Out-File "gavin/passwords.json"