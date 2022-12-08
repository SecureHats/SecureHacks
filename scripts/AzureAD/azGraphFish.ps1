<#
.Synopsis
   Helper function that gets stuff from Microsoft Graph and requests all pages recursively
.DESCRIPTION
   Helper function that gets stuff from Microsoft Graph and requests all pages recursively
.EXAMPLE
   Get-GraphRecursive -Url 'https://graph.microsoft.com/v1.0/groups?$filter=isAssignableToRole eq true' -AccessToken $AccessToken
.EXAMPLE
   Get-GraphRecursive -Url "https://graph.microsoft.com/v1.0/groups/<guid>/members?`$select=id,displayName,userPrincipalName,onPremisesDistinguishedName,onPremisesImmutableId" -AccessToken $AccessToken
#>

function Get-GraphRecursive {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Url,

        [Parameter(Mandatory = $false)]
        [string]$Filter,
        
        [Parameter(Mandatory = $false)]
        [string]$Select,

        [Parameter(Mandatory = $true)]
        [securestring]$Token,

        [Parameter(Mandatory = $true)]
        [string]$Method = 'GET',

        [Parameter(Mandatory = $true)]
        [string]$Authentication = 'OAuth'
    
        )
    
    if ($Filter) {
        $uri = '{0}?$Filter={1}' -f $Url, $Filter
        #$Uri = "https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails?`$Filter=isAdmin eq true&userType eq member"
    } else {
        $uri = $Url
<<<<<<< HEAD
    }

    if ($Select) {
         if ($uri) {
            $url = '{0}&$select={1}' -f $uri, "$select"
         } else {
            $uri = '{0}?$select={1}' -f $url, "$select"
         }
    }

    $apiResponse = Invoke-RestMethod -Uri $uri @aadRequestHeader

    $count        = 0
    $i            = 0
    $apiResult    = $apiResponse.value 
    $userNextLink = $apiResponse."@odata.nextLink"

    while ($null -ne $userNextLink) {
        $apiResponse    = (Invoke-RestMethod -uri $userNextLink @aadRequestHeader)
        $count = $count + ($apiResponse.value).count
        $i++
        if ($i -gt 50) {
            Write-host "[-] Prevent lockout"`r -NoNewline
            Start-Sleep -Seconds 1
            $i = 0
        }
        Write-Host "[+] Processed objects $($count)"`r -NoNewline
        $userNextLink   = $apiResponse."@odata.nextLink"
        $apiResult      += $apiResponse.value
    }

=======
    }

    if ($Select) {
         if ($uri) {
            $url = '{0}&$select={1}' -f $uri, "$select"
         } else {
            $uri = '{0}?$select={1}' -f $url, "$select"
         }
    }

    $apiResponse = Invoke-RestMethod -Uri $uri @aadRequestHeader

    $count        = 0
    $apiResult    = $apiResponse.value 
    $userNextLink = $apiResponse."@odata.nextLink"

    while ($null -ne $userNextLink) {
        $apiResponse    = (Invoke-RestMethod -uri $userNextLink @aadRequestHeader)
        $count = $count + ($apiResponse.value).count
        
        Write-Host "[+] Processed objects $($count)"`r -NoNewline
        $userNextLink   = $apiResponse."@odata.nextLink"
        $apiResult      += $apiResponse.value
    }

>>>>>>> 8e5bd6ec44e58037af0c3890b75a38841831cdf8
    return $apiResult
}

function Get-Members {
    [CmdletBinding()]
    [Alias()]
    Param
    (
        [Parameter(Mandatory = $false,
            Position = 0)]
        [array]$ArrayObject,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 4)]
        [String] $type,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            Position = 5)]
        [String] $roleTemplateId
    )

    switch ($type) {
        "azgroupmembers" {
            $graph = 'groups'
            $objectType = 'members'
            $userType = 'member'
        }
        "azgroupowners" {
            $graph = 'groups'
            $objectType = 'owners'
            $userType = 'owner'
        }
        "azrolemembers" {
            $graph = 'directoryRoles'
            $objectType = 'members'
            $userType = 'member'
        }
        "azapplicationowners" {
            $graph = 'applications'
            $objectType = 'owners'
            $userType = 'owner'
        }
        "azglobaladminrights" {
            $graph = 'directoryRoles'
            $objectType = 'members'
            $userType = 'member'
            $roleTemplateId = '62e90394-69f5-4237-9190-012177145e10'
        }
        "azprivroleadminrights" {
            # Can add role assignments to any other user including themselves
            $graph = 'directoryRoles'
            $objectType = 'members'
            $userType = 'member'
            $roleTemplateId = "e8611ab8-c189-46e8-94e1-60213ab1f814"
        }
        "azapplicationadmins" {
            # Can create new secrets for application service principals
            $graph = 'directoryRoles'
            $objectType = 'members'
            $userType = 'AppAdmin'
        }
        "azcloudappadmins" {
            # Can create new secrets for application service principals
            $graph = 'directoryRoles'
            $objectType = 'owners'
            $userType = 'owner'
            $roleTemplateId = '158c047a-c907-4556-b7ef-446551a6b5f7'
        }
        "azintuneadmins" {
            # Can add principals to cloud-resident security groups
            $graph = 'directoryRoles'
            $objectType = 'members'
            $userType = 'member'
            $roleTemplateId = '3a2c62db-5318-420d-8d74-23affee5d9d5'
        }
        "azapplicationtosp" {
            # Can add principals to cloud-resident security groups
            $graph = 'serviceprincipals'
            $userType = 'serviceprincipal'
        }
        Default {}
    }

    $metadata = New-Object System.Collections.ArrayList
    $dataHash = New-Object System.Collections.ArrayList
    $i = 1
    if ($roleTemplateId) {
        $uri = "$baseUrl/$graph/roleTemplateId=$($roleTemplateId)/$($objectType)"
        $accounts = (Get-GraphRecursive -Url $uri @aadRequestHeader)
        foreach ($account in $accounts) {
            $currentItem = [PSCustomObject]@{
                "UserName"          = $account.displayName
                "ObjectType"        = (($account.'@odata.id' -split "\.")[-1])
                "UserID"            = $account.id
                "UserOnPremId"      = $account.OnPremisesSecurityIdentifier
                "TenantDisplayName" = ($organizations | Where-Object id -eq (($account.'@odata.id' -split "/")[4])).displayName
                "TenantId"          = ($account.'@odata.id' -split "/")[4]
            }
            $null = $dataHash.Add($currentItem)
        }
    }
    else {
        foreach ($item in $ArrayObject) {
            Write-Host -nonewline "Processing item $($i) of $($ArrayObject.count)`r"
            $i++
            Write-Verbose "[$($graph): $($item.displayName)]`n"
            if ($type -eq "azapplicationtosp") {
                $uri = "$baseUrl/$graph/?`$filter=appid eq '$($item.appId)'"
            }
            else {
                $uri = "$baseUrl/$graph/$($item.id)/$($objectType)"
            }
            $accounts = (Get-GraphRecursive -Url $uri @aadRequestHeader)
            foreach ($account in $accounts) {
                switch ($type) {
                    "azapplicationowners" {
                        $currentItem = [PSCustomObject]@{
                            AppId                  = $item.appId
                            AppObjectId            = $item.id
                            AppName                = $item.displayName
                            "$($userType)Name"     = $account.displayName
                            "$($userType)ID"       = $account.id
                            "$($userType)Type"     = (($account.'@odata.type' -split "\.")[-1])
                            "$($userType)OnPremID" = $account.OnPremisesSecurityIdentifier
                        }
                        Write-Verbose $currentItem
                        $null = $dataHash.Add($currentItem)
                    }
                    "azapplicationtosp" {
                        $currentItem = [PSCustomObject]@{
                            AppId              = $item.appId
                            AppName            = $item.displayName
                            "$($userType)ID"   = $account.Id
                            "$($userType)Type" = (($account.'@odata.type' -split "\.")[-1])
                        }
                        $null = $dataHash.Add($currentItem)
                    }
                    default {
                        $currentItem = [PSCustomObject]@{
                            GroupName              = $item.displayname
                            GroupOnPremID          = $item.OnPremisesSecurityIdentifier
                            "$($userType)Name"     = $account.displayName
                            "$($userType)ID"       = $account.id
                            "$($userType)Type"     = (($account.'@odata.type' -split "\.")[-1])
                            "$($userType)OnPremID" = $account.OnPremisesSecurityIdentifier
                        }
                        $null = $dataHash.Add($currentItem)
                    }
                }
            }
        }
    }
    Get-Chunk -Coll $dataHash -Directory $outputDirectory -Type $type
    #return $dataHash
}
function Export-Data {
    [CmdletBinding()]
    [Alias()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline,
            Position = 0)]
        [array]$dataObject,

        [Parameter(Mandatory = $true,
            Position = 1)]
        $type
    )

    $metadata = New-Object System.Collections.ArrayList
    $dataHash = New-Object System.Collections.ArrayList

    $metadata.Add([ordered]@{
            count   = $dataObject.count
            type    = $type
            version = 4
        }) | Out-Null

    foreach ($item in $dataObject) {
        if ($item.appId) {
            $currentItem = [PSCustomObject]@{
                AppName = $item.displayname
                AppId   = $item.appId
            }
        }
        else {
            $currentItem = [PSCustomObject]@{
                DisplayName                  = $item.displayname
                OnPremisesSecurityIdentifier = $item.OnPremisesSecurityIdentifier
                ObjectId                     = $item.id
                TenantId                     = ($item.'@odata.id' -split "/")[4]
            }
        }

        if ($item.userPrincipalName) {
            $currentItem | Add-Member -MemberType NoteProperty -Name UserPrincipalName -Value "$($item.userPrincipalName)" -Force
            $currentItem | Add-Member -MemberType NoteProperty -Name TenantId -Value "$($context.tenantId)" -Force
        }

        if ($item.appId) {
            $currentItem | Add-Member -MemberType NoteProperty -Name ServicePrincipalId -Value "$($item.id)" -Force
            $currentItem | Add-Member -MemberType NoteProperty -Name ServicePrincipalType -Value "ServicePrincipal" -Force
        }

        Write-Verbose $currentItem
        $null = $dataHash.Add($currentItem)
    }
    $json = [ordered]@{}
    $json.add("meta", [ordered]@{
            count   = $dataHash.count
            type    = $type
            version = 4
        })
    $json.add("data", $dataHash)
    $json | ConvertTo-Json | Out-File "$outputDirectory\$date-$($type).json"
}
function Get-PasswordResetRights {
    $metadata = New-Object System.Collections.ArrayList
    $dataHash = New-Object System.Collections.ArrayList

    $permissionList = (Invoke-WebRequest 'https://raw.githubusercontent.com/SecureHats/SecureHacks/main/documentation/passwordResetRoles.json').content | ConvertFrom-Json
    
    foreach ($item in ($permissionList)) {
        Write-Host "       [-] Processed $($item.Role)" -ForegroundColor Yellow
        $passwordAdmins = ($RoleMembers | Where-Object GroupName -eq $item.Role)
        if ($passwordAdmins) {
            $adminRoleGroups = ($item.PasswordResetPermissions).Role

            foreach ($adminRoleGroup in $adminRoleGroups) {
                foreach ($account in ($RoleMembers | Where-Object GroupName -eq $adminRoleGroup)) {
                    foreach ($pwdAdmin in $passwordAdmins) {
                        if ($pwdAdmin.MemberName -ne $account.MemberName) {
                            $currentItem = [PSCustomObject]@{
                                UserName           = $pwdAdmin.MemberName
                                ObjectType         = $pwdAdmin.MemberType
                                UserId             = $pwdAdmin.MemberId
                                UserOnPremId       = $pwdAdmin.MemberOnPremId
                                TargetUserName     = $account.MemberName
                                TargetUserId       = $account.MemberId
                                TargetUserOnPremId = $account.MemberOnPremId
                            }
                            $null = $dataHash.Add($currentItem)
                        }
                    }
                }
            }
        }
        $passwordAdmins = ''
    }

    $json = [ordered]@{}
    $null = $json.add("data", ($dataHash | Sort-Object -unique -property Username, TargetUserName ))

    Get-Chunk -Coll $json -Directory $outputDirectory -Type "pwdresetrights"
    $json | ConvertTo-Json | Out-File "$outputDirectory\$date-azpwdresetrights.json"
}

function Get-RiskyApps {
    Write-Host "      [-] Validating [$($applications.count)] Enterprise Applications Risks" -ForegroundColor Yellow

    $permissionList = (Invoke-WebRequest 'https://raw.githubusercontent.com/SecureHats/SecureHacks/main/documentation/AppRegistrationPermissions.csv').content | ConvertFrom-Csv
    $riskyGrants = $permissionList | Where-Object Permission -in `
        (`
            'Directory.ReadWrite.All', `
            'PrivilegedAccess.ReadWrite.AzureAD', `
            'PrivilegedAccess.ReadWrite.AzureADGroup', `
            'PrivilegedAccess.ReadWrite.AzureResources', `
            'Policy.ReadWrite.ConditionalAccess', `
<<<<<<< HEAD
            'GroupMember.ReadWrite.All', `
            'Mail.Read', `
            'Mail.Read.Shared', `
            'Mail.ReadBasic', `
            'Mail.ReadWrite', `
            'Mail.ReadWrite.Shared', `
            'Mail.Send', `
            'Mail.Send.Shared'
=======
            'GroupMember.ReadWrite.All' `
>>>>>>> 8e5bd6ec44e58037af0c3890b75a38841831cdf8
        )

    $dataHash           = New-Object System.Collections.ArrayList
    $riskyApps          = New-Object System.Collections.ArrayList
    $permissionObjects  = @()
    
    foreach ($application in $applications) {
        foreach ($riskyGrant in $riskyGrants) {
            if ($application.requiredResourceAccess.resourceaccess.id -contains $riskyGrant.id) {
                $permissionObjects += ($riskyGrant.Permission)
            }

            if ($permissionObjects.count -gt 0) {
                $null = $riskyApps.add($application)
            }
        }

        if ($permissionObjects.count -gt 0) {
                    
            $currentItem = [PSCustomObject]@{
                Id              = $application.Id
                DisplayName     = $application.displayname
                createdDateTime = $application.createdDateTime
                Permission      = $permissionObjects | Sort-Object -Unique
            }

            if ($application.passwordCredentials.keyId) {
                $currentItem | Add-Member -MemberType NoteProperty -Name Credentials -Value $application.passwordCredentials -Force
            }

            if ($application.keyCredentials.value) {
                $currentItem | Add-Member -MemberType NoteProperty -Name keyCredentials -Value $application.keyCredentials -Force
            }
                    
            $null = $dataHash.Add($currentItem)
        }
        $permissionObjects = @()
                
    }
            
    $json = [ordered]@{}
    $null = $json.add("data", ($dataHash))

    Get-Chunk -Coll $json -Directory $outputDirectory -Type "riskyApps"
    $json | ConvertTo-Json -depth 10 | Out-File "$outputDirectory\$date-azriskyApps.json"
}

#https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-beta
function Get-AdminDetails {
    Write-Host "   [-] Processing Password Reset Permissions" -ForegroundColor Yellow
    $metadata = New-Object System.Collections.ArrayList
    $dataHash = New-Object System.Collections.ArrayList

            
    foreach ($account in ($roleMembers | Where-Object GroupName -like "*Admin*")) {
    
        try {
            $uri = "$baseUrl/users/$($account.memberID)?select=id, displayName, userPrincipalName, jobTitle, accountEnabled, createdDateTime, lastPasswordChangeDateTime, passwordProfile, passwordPolicies"
            
            if ($signInActivity) { $uri = "$baseUrl/users/$($account.memberID)?select=id, displayName, userPrincipalName, jobTitle, accountEnabled, createdDateTime, lastPasswordChangeDateTime, passwordProfile, passwordPolicies, signInActivity"}
            
            $adminUser = Invoke-RestMethod -uri $uri @aadRequestHeader
        
            $currentItem = [PSCustomObject]@{
            accountEnabled             = $adminUser.accountEnabled
            UserName                   = $adminUser.displayName
            UserPrincipalName          = $adminUser.userPrincipalName
            UserId                     = $adminUser.id
            jobTitle                   = $adminUser.jobTitle
            createdDateTime            = $adminUser.createdDateTime
            lastPasswordChangeDateTime = $adminUser.lastPasswordChangeDateTime
            lastPasswordChangeInDays   = ($adminUser.lastPasswordChangeDateTime - (Get-Date)).days
            passwordProfile            = $adminUser.passwordProfile
            passwordPolicies           = $adminUser.passwordPolicies
            signInActivity              = $adminUser.signInActivity.lastSignInDateTime
            
        }
        $null = $dataHash.Add($currentItem)
        $adminUser = ''
        }
        catch {
            #Not a user object
        }  
    }
    
    
    $json = [ordered]@{}
    $json.add("data", ($dataHash | Sort-Object -unique -property Username, TargetUserName ))

    Get-Chunk -Coll $json -Directory $outputDirectory -Type "admindetails"
    $json | ConvertTo-Json | Out-File "$outputDirectory\$date-azadmindetails.json"
}

function Get-GraphToken {
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String[]]
        [ValidateSet("MSGraph", "Azure", "Monitor")]
        $Client,    
        [Parameter(Mandatory = $False)]
        [String]
        $Resource = "https://graph.microsoft.com"
        
    )
    
    switch ($Client) {
        "MSGraph" {
            $body = @{
                "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                "resource"  = "https://graph.microsoft.com/"
            }
        }
        "Azure" {
            $body = @{
                "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                "resource"  = "https://management.core.windows.net"
            }
        }
        "Monitor" {
            $body = @{
                "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                "resource"  = "https://monitor.azure.com/"
                "scope" = [System.Web.HttpUtility]::UrlEncode("https://monitor.azure.com//.default")
            }
        }
    }

    # Login Process
    $authResponse = Invoke-RestMethod `
        -UseBasicParsing `
        -Method Post `
        -Uri "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0" `
        -Body $body
    
    Write-Output $authResponse.message
    $continue = $true
    
    $body = @{
        "client_id"  = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
        "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
        "code"       = $authResponse.device_code
    }
    while ($continue) {
        Start-Sleep -Seconds $authResponse.interval
        $total += $authResponse.interval

        if ($total -gt ($authResponse.expires_in)) {
            Write-Error "Timeout occurred"
            return
        }          
        try {
            $global:graphToken = Invoke-RestMethod `
                -UseBasicParsing `
                -Method Post `
                -Uri "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0 " `
                -Body $body `
                -ErrorAction SilentlyContinue
        }
        catch {
            $details = $_.ErrorDetails.Message | ConvertFrom-Json
            $continue = $details.error -eq "authorization_pending"
            Write-Output "Waiting for approval: $($continue)"

            if (!$continue) {
                Write-Error $details.error_description
                return
            }
        }
        if($graphToken) {
            break
        }
    }
}

function Get-Chunk($Coll, $Type, $Directory) {
    $Count = $Coll.Count

    if ($null -eq $Coll) {
        $Coll = New-Object System.Collections.ArrayList
    }

    # ConvertTo-Json consumes too much memory on larger objects, which can have millions
    # of entries in a large tenant. Write out the JSON structure a bit at a time to work
    # around this. This is a bit inefficient, but makes this work when the tenant becomes
    # too large.
    $FileName = $Directory.path + [IO.Path]::DirectorySeparatorChar + $date + "-" + $($Type) + ".json"
    try {
        $Stream = [System.IO.StreamWriter]::new($FileName)

        # Write file header JSON
        $Stream.WriteLine('{')
        $Stream.WriteLine("`t""meta"": {")
        $Stream.WriteLine("`t`t""count"": $Count,")
        $Stream.WriteLine("`t`t""type"": ""az$($Type)"",")
        $Stream.WriteLine("`t`t""version"": 4")
        $Stream.WriteLine("`t},")

        # Write data JSON
        $Stream.WriteLine("`t""data"": [")
        $Stream.Flush()

        $chunksize = 250
        $chunkarray = @()
        $parts = [math]::Ceiling($coll.Count / $chunksize)
        Write-Verbose "    [-] Chopping and Chunking data in $chunksize items"

        if ($Coll.count -eq 1) {
            $chunkarray = $Coll
        }
        else {
            for ($n = 0; $n -lt $parts; $n++) {
                $start = $n * $chunksize
                $end = (($n + 1) * $chunksize) - 1
                $chunkarray += , @($coll[$start..$end])
            }
            $Count = $chunkarray.Count
        }

        $chunkcounter = 1
        $jsonout = ""

        ForEach ($chunk in $chunkarray) {
            if ($Count -gt 0) {
                Write-Host -nonewline "Writing data block $chunkcounter of $Count`r"
            }
            $jsonout = ConvertTo-Json($chunk) -Depth 100
            $jsonout = $jsonout.trimstart("[`r`n").trimend("`r`n]")
            $Stream.Write($jsonout)
            If ($chunkcounter -lt $Count) {
                $Stream.WriteLine(",")
            }
            Else {
                $Stream.WriteLine("")
            }
            $Stream.Flush()
            $chunkcounter += 1
        }
        $Stream.WriteLine("`t]")
        $Stream.WriteLine("}")
    }
    finally {
        $Stream.close()
    }
}
function Start-GraphFish {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter()]
        [switch]
        $Hound,

        [switch]
        $includeUsersAndGroups,

        [switch]
        $signInActivity,

        [Parameter()]
        [string]$resourceType,

        [Parameter()]
        [string]$servicePrincipalId,

        [Parameter()]
        [string]$servicePrincipalKey,

        [Parameter()]
        [string]$tenantId
    )

    Begin {
        #Set-StrictMode -Version Latest
        #$ErrorActionPreference = 'SilentlyContinue'

        $logo = "
                  ╭━━━╮       ╭╮ ╭━━━╮   ╭╮
                  ┃╭━╮┃       ┃┃ ┃╭━━╯   ┃┃
        ╭━━┳━━━╮  ┃┃ ╰╋━┳━━┳━━┫╰━┫╰━━┳┳━━┫╰━╮
        ┃╭╮┣━━┃┣━━┫┃╭━┫╭┫╭╮┃╭╮┃╭╮┃╭━━╋┫━━┫╭╮┃
        ┃╭╮┃┃━━╋━━┫╰┻━┃┃┃╭╮┃╰╯┃┃┃┃┃  ┃┣━━┃┃┃┃
        ╰╯╰┻━━━╯  ╰━━━┻╯╰╯╰┫╭━┻╯╰┻╯  ╰┻━━┻╯╰╯
                           ┃┃
                           ╰╯"

            $date = get-date -f yyyyMMddhhmmss
            $baseUrl = 'https://graph.microsoft.com/beta'
            $mngtUrl = 'https://management.azure.com'
            $outputDirectory = $(Get-Location)

        try {
            if ($null -ne $graphToken) {
                [datetime]$expiresOn = $graphToken.expiresOn
                $refresh = ($expiresOn - (get-date)).minutes
                Write-Host $refresh
            }
            else {
                $refresh = 0
            }
        }
        catch {
            $refresh = 0
        }
        if ($refresh -le 1) {
            Write-Output "Create a Graph Token using the Get-GraphToken command"
            Get-GraphToken -Client MSGraph
        }
    }
    Process {
        Clear-Host
        Write-Host $logo -ForegroundColor White
        Write-Output "      -- L E T S   S T A R T   F I S H I N G --"

        #current context
        $context = az account show | ConvertFrom-Json
        Write-Output "`nCurrent Context:" $context
        Write-Output "Token valid until:" $($graphToken.expiresOn)

        #region Active Directory
        $aadRequestHeader = @{
            "Token"          = ($graphToken.access_token | ConvertTo-SecureString -AsPlainText -Force)
            "Authentication" = 'OAuth'
            "Method"         = 'GET'
        }

        if ($resourceType -eq 'AzureAd') {
            Write-Output "`n[+] Collecting RAW tenant data"
            Write-Host "   [-] Collecting Directory Roles" -ForegroundColor Yellow
            $organizations = (Get-GraphRecursive @aadRequestHeader -Url "$baseUrl/organization")
            
            if ($includeUsersAndGroups) { 
                Write-Host "   [-] Collecting Users and Groups ( This may take very long! )" -ForegroundColor Yellow
                $users = (Get-GraphRecursive @aadRequestHeader -Url "$baseUrl/users")
                $groups = (Get-GraphRecursive @aadRequestHeader -Url "$baseUrl/groups")
<<<<<<< HEAD
                
                Write-Host "   [-] Collecting MFA status for internal users ( This may take very long! )" -ForegroundColor Yellow
                $mfaStatusInternal = (Get-GraphRecursive @aadRequestHeader -Url "$baseUrl/reports/authenticationMethods/userRegistrationDetails" -Filter "UserType eq 'Member'")
            }

            Write-Host "   [-] Collecting Directory Roles" -ForegroundColor Yellow
            $directoryRoles = (Get-GraphRecursive @aadRequestHeader -Url "$baseUrl/directoryRoles")
            
            Write-Host "   [-] Collecting Enterprise Applications" -ForegroundColor Yellow
            $applications = (Get-GraphRecursive @aadRequestHeader -Url "$baseUrl/applications")

            Write-Host "   [-] Collecting Service Principals" -ForegroundColor Yellow
            $serviceprincipals = (Get-GraphRecursive @aadRequestHeader -Url "$baseUrl/serviceprincipals")

            Write-Host "   [-] Collecting External Users" -ForegroundColor Yellow
            $externalUsers = (Get-GraphRecursive @aadRequestHeader -Url "$baseUrl/users" -filter "UserType eq 'Guest'" -select "id, displayName, creationType, userPrincipalName, externalUserState, externalUserStateChangeDateTime, createdDateTime, signInActivity")

            Write-Host "   [-] Collecting Role Members" -ForegroundColor Yellow
            Get-Members -ArrayObject $directoryRoles -type azrolemembers
            $roleMembers = (Get-Content $outputDirectory\$date-azrolemembers.json | ConvertFrom-Json).data

            Write-Output "[+] Processing RAW tenant data"
            Write-Host "   [-] Processing Organizations" -ForegroundColor Yellow
            $organizations | ConvertTo-Json -Depth 10 | Out-File "$outputDirectory\$date-tenants.json"
            if ($includeUsersAndGroups){
                Write-Host "   [-] Processing [$($users.count)] Users" -ForegroundColor Yellow
                #Get-Chunk -Type "azuseraccounts" -Coll $users -Directory $outputDirectory -type "users"
                Get-Chunk -`Type "azmfastatus" -Coll $mfaStatusInternal | Out-File "$outputDirectory\$date-mfaStatus.json"
                
                Write-Host "   [-] Processing [$($groups.count)] Groups" -ForegroundColor Yellow
                $groups | ConvertTo-Json -Depth 10 | Out-File "$outputDirectory\$date-groups.json"
                
                $groupsArray = @(
                    "azgroupmembers"
                    "azgroupowners"
                )

                foreach ($grp in $groupsArray) {
                    Get-Members -ArrayObject $groups -Type $grp
                }
            }
            
=======
            }
            
            Write-Host "   [-] Collecting Directory Roles" -ForegroundColor Yellow
            $directoryRoles = (Get-GraphRecursive @aadRequestHeader -Url "$baseUrl/directoryRoles")
            
            Write-Host "   [-] Collecting Enterprise Applications" -ForegroundColor Yellow
            $applications = (Get-GraphRecursive @aadRequestHeader -Url "$baseUrl/applications")

            Write-Host "   [-] Collecting Service Principals" -ForegroundColor Yellow
            $serviceprincipals = (Get-GraphRecursive @aadRequestHeader -Url "$baseUrl/serviceprincipals")

            Write-Host "   [-] Collecting External Users" -ForegroundColor Yellow
            $externalUsers = (Get-GraphRecursive @aadRequestHeader -Url "$baseUrl/users" -filter "UserType eq 'Guest'" -select "id, displayName, creationType, userPrincipalName, externalUserState, externalUserStateChangeDateTime, createdDateTime")

            Write-Host "   [-] Collecting Role Members" -ForegroundColor Yellow
            Get-Members -ArrayObject $directoryRoles -type azrolemembers
            $roleMembers = (Get-Content $outputDirectory\$date-azrolemembers.json | ConvertFrom-Json).data

            Write-Output "[+] Processing RAW tenant data"
            Write-Host "   [-] Processing Organizations" -ForegroundColor Yellow
            $organizations  | ConvertTo-Json -Depth 10 | Out-File "$outputDirectory\$date-tenants.json"
            if ($includeUsersAndGroups){
                Write-Host "   [-] Processing [$($users.count)] Users" -ForegroundColor Yellow
                $users | Get-Chunk -Coll $users -Directory $outputDirectory -type "users"
                
                Write-Host "   [-] Processing [$($groups.count)] Groups" -ForegroundColor Yellow
                $groups | ConvertTo-Json -Depth 10 | Out-File "$outputDirectory\$date-groups.json"
                
                $groupsArray = @(
                    "azgroupmembers"
                    "azgroupowners"
                )

                foreach ($grp in $groupsArray) {
                    Get-Members -ArrayObject $groups -Type $grp
                }
            }
            
>>>>>>> 8e5bd6ec44e58037af0c3890b75a38841831cdf8
            Write-Host "   [-] Processing [$($directoryRoles.count)] Directory roles" -ForegroundColor Yellow
            $directoryRoles | ConvertTo-Json -Depth 10 | Out-File "$outputDirectory\$date-directoryroles.json"
            
            Write-Host "   [-] Processing [$($externalUsers.count)] External users" -ForegroundColor Yellow
            $externalUsers | ConvertTo-Json -Depth 10 | Out-File "$outputDirectory\$date-externalUsers.json"

            $pendingUsers = $externalUsers | Where-Object externalUserState -notin @('Accepted', $null) | Where-Object { (New-TimeSpan -Start (Get-Date($_.externalUserStateChangeDateTime)) -End (Get-Date)).Days -gt 90 }
            Write-Host "      [-] Processing [$($pendingUsers.count)] External users with more than 90 pending status" -ForegroundColor Yellow
            $pendingUsers | ConvertTo-Json -Depth 10 | Out-File "$outputDirectory\$date-pendingExternalUsers.json"

            Write-Host "   [-] Processing [$($roleMembers.count)] role assignments" -ForegroundColor Yellow
            Get-Chunk -Type "azglobaladminrights" -Directory $outputDirectory -coll ($roleMembers | Where-Object GroupName -eq "Global Administrator")
            Get-Chunk -Type "azprivroleadminrights" -Directory $outputDirectory -coll ($roleMembers | Where-Object GroupName -eq "Privileged Role Administrator")
            Get-Chunk -Type "azapplicationadmins" -Directory $outputDirectory -coll ($roleMembers | Where-Object GroupName -eq "Application Administrator")
            Get-Chunk -Type "azroleGroupAssignments" -Directory $outputDirectory -coll ($roleMembers | Where-Object memberType -eq 'group')

            Write-Host "   [-] Processing [$($applications.count)] applications" -ForegroundColor Yellow
<<<<<<< HEAD
            $applications | ConvertTo-Json -Depth 10 | Out-File "$outputDirectory\$date-applications.json"

            $expiredApps = @()
            foreach ($app in $applications) {
                if ($app.passwordCredentials) {
                    $passwordDate = ($app.passwordCredentials | Sort-Object endDateTime -Descending)[0]
                    $span = New-TimeSpan -Start (Get-Date) -End (Get-Date -Date $passwordDate.endDateTime)
                    if ($span.Days -lt -90) {
                        $expiredApps += $app
                    }
                }
            }

            $expiredApps | ConvertTo-Json -Depth 10 | Out-File "$outputDirectory\$date-expiredApps.json"

            $longlifeApps = @()
            foreach ($app in $applications) {
                if ($app.passwordCredentials) {
                    $passwordDate = ($app.passwordCredentials | Sort-Object endDateTime -Descending)[0]
                    $span = New-TimeSpan -Start (Get-Date $passwordDate.startDateTime) -End (Get-Date -Date $passwordDate.endDateTime)
                    if ($span.Days -gt 366) {
                        $longlifeApps += $app
                    }
                }
            }

            $longlifeApps | ConvertTo-Json -Depth 10 | Out-File "$outputDirectory\$date-longlifeApps.json"

            Write-Host "   [-] Processing [$($serviceprincipals.count)] serviceprincipals" -ForegroundColor Yellow
            $serviceprincipals | ConvertTo-Json -Depth 10 | Out-File "$outputDirectory\$date-serviceprincipals.json"
            
            $expiredSpns = @()
            foreach ($spn in $serviceprincipals) {
                if ($spn.passwordCredentials) {
                    $passwordDate = ($spn.passwordCredentials | Sort-Object endDateTime -Descending)[0]
                    $span = New-TimeSpan -Start (Get-Date) -End (Get-Date -Date $passwordDate.endDateTime)
                    if ($span.Days -lt -90) {
                        $expiredSpns += $spn
                    }
                }
            }

            $expiredSpns | Select-Object Id, displayName, createdDateTime, passwordCredentials | ConvertTo-Json -Depth 10 | Out-File "$outputDirectory\$date-expiredSpns.json"

            $longlifeSpns = @()
            foreach ($spn in $serviceprincipals) {
                if ($spn.passwordCredentials) {
                    $passwordDate = ($spn.passwordCredentials | Sort-Object endDateTime -Descending)[0]
                    $span = New-TimeSpan -Start (Get-Date -Date $passwordDate.startDateTime) -End (Get-Date -Date $passwordDate.endDateTime)
                    if ($span.Days -gt 366) {
                        $longlifeSpns += $spn
                    }
                }
            }

            $longlifeSpns | Select-Object Id, displayName, createdDateTime, passwordCredentials | ConvertTo-Json -Depth 10 | Out-File "$outputDirectory\$date-longlifeSpns.json"

=======
            $applications  | ConvertTo-Json -Depth 10 | Out-File "$outputDirectory\$date-applications.json"

            Write-Host "   [-] Processing [$($serviceprincipals.count)] serviceprincipals" -ForegroundColor Yellow
            $serviceprincipals  | ConvertTo-Json -Depth 10 | Out-File "$outputDirectory\$date-serviceprincipals.json"
            
>>>>>>> 8e5bd6ec44e58037af0c3890b75a38841831cdf8
            $appsArray = @(
                "azapplicationowners"
                "azapplicationtosp"
            )
            
            foreach ($app in $appsArray) {
                Get-Members -ArrayObject $applications -Type $app
            }
            
<<<<<<< HEAD
            $namedLocations = (invoke-RestMethod -Uri 'https://graph.microsoft.com/beta/identity/conditionalAccess/namedLocations' @aadRequestHeader).value.displayName
            $namedLocations | ConvertTo-Json -Depth 10 | Out-File "$outputDirectory\$date-namedLocations.json"

=======
>>>>>>> 8e5bd6ec44e58037af0c3890b75a38841831cdf8
            Get-RiskyApps     
            Get-AdminDetails
            Get-PasswordResetRights
            
            if ($hound) {
                Write-Output "Building AzureHound Export"
                export-data $organizations -type aztenants
                export-data $users -type azusers
                export-data $groups -type azgroups
                export-data $directoryRoles -type azdirectoryroles
                export-data $applications -type azapplicationowners
            }           
        }

        if ($resourceType -eq 'Azure') {
            #region Azure
            #$graphToken = Get-GraphToken -resource Azure
            #$requestBody = @{
            #    "Token"          = ($graphToken.accessToken | ConvertTo-SecureString -AsPlainText -Force)
            #    "Authentication" = 'OAuth'
            #    "Method"         = 'GET'
            #}

            $subscriptions = (Get-GraphRecursive @aadRequestHeader -api '2020-01-01' -Url "$mngtUrl/subscriptions")
            foreach ($subid in $subscriptions.subscriptionId) {
                $subroles = (Get-GraphRecursive @aadRequestHeader -api '2018-07-01' -Url "$mngtUrl/subscriptions/$subId/providers/Microsoft.Authorization/roleDefinitions")
                $subRoleAssignments = (Get-GraphRecursive @aadRequestHeader -api '2020-04-01-preview' -Url "$mngtUrl/subscriptions/$subId/providers/Microsoft.Authorization/roleAssignments")
                $customRoles = $subroles.Properties | Where-Object type -ne 'BuiltInRole'

                ($subRoleAssignments | Where-Object { $_.properties.roledefinitionId -like '*8e3af657-a8ff-443c-a75c-2fe8c4bcb635*' }).properties | ConvertTo-CSV | out-file "$($subId)-owners.csv"
                ($subRoleAssignments | Where-Object { $_.properties.roledefinitionId -like '*b24988ac-6180-42a0-ab88-20f7382dd24c*' }).properties | ConvertTo-CSV | out-file "$($subId)-contributors.csv"
                ($subRoleAssignments | Where-Object { $_.properties.roledefinitionId -like '*18d7d88d-d35e-4fb5-a5c3-7773c20a72d9*' }).properties | ConvertTo-CSV | out-file "$($subId)-useraccessadmins.csv"
                ($subRoleAssignments | Where-Object { $_.properties.roledefinitionId -like '*9980e02c-c2be-4d73-94e8-173b1dc7cf3c*' }).properties | ConvertTo-CSV | out-file "$($subId)-vmcontributors.csv"
                ($subRoleAssignments | Where-Object { $_.properties.roledefinitionId -like '*00482a5a-887f-4fb3-b363-3b7fe8e74483*' }).properties | ConvertTo-CSV | out-file "$($subId)-kvAdmins.csv"
                ($subRoleAssignments | Where-Object { $_.properties.roledefinitionId -like '*17d1049b-9a84-46fb-8f53-869881c3d3ab*' }).properties | ConvertTo-CSV | out-file "$($subId)-stgContributors.csv"
                ($subRoleAssignments | Where-Object { $_.properties.roledefinitionId -like '*81a9662b-bebf-436f-a333-f67b29880f12*' }).properties | ConvertTo-CSV | out-file "$($subId)-stgKeyOperators.csv"
            }
            #endregion Azure
        }
    }
    End {}
}

# #Current User Permissions
# $permissions = (Get-GraphRecursive -Url "$mngtUrl/subscriptions/$subId/resourcegroups/{resourceGroupName}/providers/Microsoft.Authorization/permissions" @requestBody -api '2018-07-01')

# foreach ($directoryRole in $directoryRoles) {
#     Write-Output "[Role: $($directoryRole.displayName)]"

#     $uri = "$baseUrl/directoryRoles/$($directoryRole.id)/members"

#     $directoryRoleMembers = (Get-GraphRecursive -Url $uri @requestBody)
#     Write-Output $directoryRoleMembers | ConvertTo-Json -Depth 100 | Out-File .\outputs\$($directoryRole.id).json
# }

# $    = az account get-access-token | ConvertFrom-Json
# Write-Host "retrieved token" -ForegroundColor Green
# Write-Output $token
# # Get Azure Resource Groups
# $endpoint = "https://management.azure.com/subscriptions/$($token.subscription)/resourcegroups?api-version=2019-08-01"
# $headers = @{}
# $headers.Add("Authorization", "$("bearer") " + " " + "$($token.accesstoken)")
# $resourceGroups = Invoke-RestMethod -Method Get `
#     -Uri $endpoint `
#     -Headers $Headers
# Write-host "retrieved Resource groups" -ForegroundColor Green
# Write-Output $resourceGroups.value.name

# $baseUrl = 'https://management.azure.com'
# $subs = (Invoke-RestMethod -Uri "$baseUrl/subscriptions?api-version=2020-01-01" -Headers $headers).value

# foreach ($sub in $subs) {
#     $uri = "https://management.azure.com/subscriptions/$($sub.subscriptionId)/resourcegroups?api-version=2019-08-01"
#     (Invoke-RestMethod -Method Get `
#         -Uri $endpoint `
#         -Headers $Headers).value
# }

# Get-Assignments -ArrayObject $users @requestBody -objectType azusers


# (Invoke-RestMethod @requestBody -uri "$baseUrl/serviceprincipals?`$filter=appid eq '$applicationId'").value
# "https://graph.microsoft.com/beta/users/?`$filter=id eq '$($UserAccount)'&`$select=onPremisesDistinguishedName, displayName" `
#     -accessToken $accessToken)
