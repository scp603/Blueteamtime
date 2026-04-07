$key = Read-Host -AsSecureString "FoxtrotTeamKeyForBlueTeam26cday3"
$keyPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($key)
)
$keyBytes = [System.Text.Encoding]::UTF8.GetBytes($keyPlain.PadRight(32).Substring(0,32))

$passwords = @{
    "example" = "examplepass"
}

$encrypted = @{}
foreach ($user in $passwords.Keys) {
    $secureStr = ConvertTo-SecureString $passwords[$user] -AsPlainText -Force
    $encrypted[$user] = ConvertFrom-SecureString $secureStr -Key $keyBytes
}

$encrypted | ConvertTo-Json | Out-File "passwords.json"