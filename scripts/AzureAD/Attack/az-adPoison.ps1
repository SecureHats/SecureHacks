
$payload = @{
    "accountEnabled"= $true
    "displayName"= "Adele Vance"
    "mailNickname"= "AdeleV"
    "userPrincipalName"= '{0}{1}' -f (New-Guid).Guid,  "@securehatsnl.onmicrosoft.com"
    "passwordProfile" = @{
      "forceChangePasswordNextSignIn"= $true
      "password"= "xWwvJ]6NMw+bWH-d"
    }
}
do {
    $payload = @{
        "accountEnabled"= $true
        "displayName"= "Adele Vance"
        "mailNickname"= "AdeleV"
        "userPrincipalName"= '{0}{1}' -f (New-Guid).Guid,  "@securehatsnl.onmicrosoft.com"
        "passwordProfile" = @{
          "forceChangePasswordNextSignIn"= $true
          "password"= "xWwvJ]6NMw+bWH-d"
        }
    }

    $user = invoke-restMethod -Uri "https://graph.microsoft.com/beta/users" @requestHeader `
        -Body ($payload | ConvertTo-Json) `
        -ContentType 'application/json' `
        -Method POST
    # $user = invoke-restMethod -Uri "https://graph.microsoft.com/beta/users/$($user.id)" @requestHeader -Method DELETE
    Write-Host "Accounts created $i`r" -NoNewline 
    $i++
} while ( $i -lt 300000 )