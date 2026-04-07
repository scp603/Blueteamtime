# TODO: create a list of users, and a list of salted & hashed passwords that are hard coded here

# $url = "https://github.com/scp603/Blueteamtime/blob/main/gavin/passwords.json"
$url = "http://127.0.0.1/gavin/passwords.json"
$raw = Invoke-WebRequest -Uri $url
$encrypted = $raw.Content | ConvertFrom-Json

# TODO: check if each user is part of hard coded list of users here

$keyInput = Read-Host -AsSecureString "Enter key"
$keyPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($keyInput)
)
$keyBytes = [System.Text.Encoding]::UTF8.GetBytes($keyPlain.PadRight(32).Substring(0,32))

foreach ($user in $encrypted.PSObject.Properties) {
    $securePassword = $user.Value | ConvertTo-SecureString -Key $keyBytes
    # TODO: get the salted hashed value of the password to see if it's listed within the hard coded passwords
    Set-ADAccountPassword -Identity $user.Name `
        -NewPassword $securePassword `
        -Reset
    Write-Host "Password changed for $($user.Name)"
}
