# $url = "https://github.com/scp603/Blueteamtime/blob/main/gavin/passwords.json"
$url = "http://127.0.0.1/gavin/passwords.json"
$raw = Invoke-WebRequest -Uri $url
$encrypted = $raw.Content | ConvertFrom-Json

$keyInput = Read-Host -AsSecureString "Enter key"
$keyPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($keyInput)
)
$keyBytes = [System.Text.Encoding]::UTF8.GetBytes($keyPlain.PadRight(32).Substring(0,32))

foreach ($user in $encrypted.PSObject.Properties) {
    Write-Output $user.Value
}