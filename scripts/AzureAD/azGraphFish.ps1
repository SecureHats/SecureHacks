<#
.Synopsis
   Helper function that gets stuff from Microsoft Graph and requests all pages recursively
.DESCRIPTION
   Helper function that gets stuff from Microsoft Graph and requests all pages recursively
.EXAMPLE
   Get-GraphRecursive -Url 'https://graph.microsoft.com/v1.0/groups?$filter=isAssignableToRole eq true' -AccessToken $AccessToken
.EXAMPLE
   Get-GraphRecursive -Url "https://graph.microsoft.com/v1.0/groups/<guid>/members?`$select=id, displayName, userPrincipalName, onPremisesDistinguishedName, onPremisesImmutableId" -AccessToken $AccessToken
#>
function Get-GraphRecursive {
    [CmdletBinding()]
    [Alias()]
    Param
    (
        [Parameter(Mandatory = $true,
            Position = 0)]
        [securestring]$Token,

        # Graph access token
        [Parameter(Mandatory = $false,
            Position = 1)]
        [string]$Method,

        # Graph access token
        [Parameter(Mandatory = $false,
            Position = 2)]
        [string]$Api,

        [Parameter(Mandatory = $true,
            Position = 3)]
        [string]$Authentication,

        [Parameter(Mandatory = $false,
            Position = 4)]
        [string]$filter,

        [Parameter(Mandatory = $false,
            Position = 5)]
        [string]$select,

        # Graph url
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 6)]
        [String] $Url
    )

    #Write-Host "Fetching url $Url"
    if ($api) {
        $url = '{0}?api-version={1}' -f $Url, $API
        if ($filter) {
            $url = '{0}/?filter={2}&api-version={1}' -f $Url, $API, $filter
        }
    }
    if ($select) {
        $url = '{0}?$select={1}' -f $url, "$select"
    }

    $result = Invoke-RestMethod -Uri $Url -method $method -Authentication $Authentication -token $token -Verbose:$false
    if ($result.value) {
        $Result.value
    }

    # Calls itself when there is a nextlink, in order to get next page
    try {
        if ($result.'@odata.nextLink') {
            Get-GraphRecursive -Url $result.'@odata.nextLink' -method $method -Authentication $Authentication -token $token

            $resultCount = ($Result.value).count
            if ($resultCount -gt 999) {
                Write-Host "Processing $($resultCount) items"
            }
        }
    }
    catch {
        # Nothing to process
    }
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
            #Write-Output $currentItem
            $null = $dataHash.Add($currentItem)
        }
    }
    else {
        foreach ($item in $ArrayObject) {
            Write-Output "Processing item $($i) of $($ArrayObject.count) - '$($item.displayName)'"
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
                            "$($userType)Type"     = (($account.'@odata.id' -split "\.")[-1])
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
                            "$($userType)Type" = (($account.'@odata.id' -split "\.")[-1])
                        }
                        Write-Verbose $currentItem
                        $null = $dataHash.Add($currentItem)
                    }
                    default {
                        $currentItem = [PSCustomObject]@{
                            GroupName              = $item.displayname
                            GroupID                = $item.id
                            GroupOnPremID          = $item.OnPremisesSecurityIdentifier
                            "$($userType)Name"     = $account.displayName
                            "$($userType)ID"       = $account.id
                            "$($userType)Type"     = (($account.'@odata.id' -split "\.")[-1])
                            "$($userType)OnPremID" = $account.OnPremisesSecurityIdentifier
                        }
                        Write-Verbose $currentItem
                        $null = $dataHash.Add($currentItem)
                    }
                }
            }
        }
    }
    Get-Chunk -Coll $dataHash -Directory $outputDirectory -Type $type
    return $dataHash
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
    Write-Output "Get Password Reset Permissions"
    $metadata = New-Object System.Collections.ArrayList
    $dataHash = New-Object System.Collections.ArrayList

    $permissionList = (Invoke-WebRequest 'https://raw.githubusercontent.com/SecureHats/SecureHacks/main/documentation/passwordResetRoles.json').content | ConvertFrom-Json

    foreach ($item in ($permissionList)) {
        Write-Host $item.Role -ForegroundColor Yellow
        $passwordAdmins = ($RoleMembers | Where-Object GroupName -eq $item.Role)
        if ($passwordAdmins) {
            $adminRoleGroups = ($item.PasswordResetPermissions).Role
            Write-Output "Admin Roles: $($adminRoleGroups)"

            foreach ($adminRoleGroup in $adminRoleGroups) {
                #Write-Output "Admin Role Group" $adminRoleGroup
                #Write-Output ($RoleMembers | Where-Object GroupName -eq $adminRoleGroup)
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

function Get-GraphToken {
    [cmdletbinding()]
    param( 
        [Parameter()]
        $ClientID = '1950a258-227b-4e31-a9cf-717495945fc2',
        
        [Parameter()]
        $TenantID = 'common',
        
        [Parameter()]
        $Resource = "https://graph.microsoft.com/",

        [Parameter()]
        $Scope = "reports.Read",
        
        # Timeout in seconds to wait for user to complete sign in process
        [Parameter(DontShow)]
        $Timeout = 300
    )

        if ($_graphToken){
            if($_graphToken.resource -ne 'https://graph.microsoft.com/'){ $_graphToken = ''}
            if($_graphToken.clientID -ne '1950a258-227b-4e31-a9cf-717495945fc2'){ $_graphToken = ''}
            if(($expiry - (get-date)).minutes -lt 5){ $_graphToken = ''}
        }

    try {
        $deviceCodeRequestParams = @{
            Method = 'POST'
            Uri    = "https://login.microsoftonline.com/$TenantID/oauth2/devicecode"
            Body   = @{
                resource  = $Resource
                client_id = $ClientId
                #scope = "$Resource/Reports.Read"
            }
        }
        $deviceCodeRequest = Invoke-RestMethod @deviceCodeRequestParams
        Write-Host $deviceCodeRequest.message -ForegroundColor Yellow

        $tokenRequestParams = @{
            Method = 'POST'
            Uri    = "https://login.microsoftonline.com/$TenantId/oauth2/token"
            Body   = @{
                grant_type = "urn:ietf:params:oauth:grant-type:device_code"
                code       = $deviceCodeRequest.device_code
                client_id  = $ClientId
            }
        }
        $timeoutTimer = [System.Diagnostics.Stopwatch]::StartNew()
        while ([string]::IsNullOrEmpty($_graphToken.access_token)) {
            if ($timeoutTimer.Elapsed.TotalSeconds -gt ($deviceCodeRequest.expires_in)) {
                throw 'Login timed out, please try again.'
            }
            $global:_graphToken = try {
                Invoke-RestMethod @tokenRequestParams -ErrorAction Stop
            }
            catch {
                $message = $_.ErrorDetails.Message | ConvertFrom-Json
                if ($message.error -ne "authorization_pending") {
                    throw
                }
            }
            Start-Sleep -Seconds 1
        }
    }
    finally {
        try {
            $timeoutTimer.Stop()
        }
        catch {
            # We don't care about errors here
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
        Write-Output "Collections" $($Coll)
        Write-Output "Chopping and Chunking data in $chunksize items"

        if ($Coll.count -eq 1) {
            $chunkarray = $Coll
        }
        else {
            for ($n = 0; $n -lt $parts; $n++) {
                $start = $n * $chunksize
                $end = (($n + 1) * $chunksize) - 1
                $chunkarray += , @($coll[$start..$end])
                Write-Host $($chunkarray)
            }
            $Count = $chunkarray.Count
        }

        $chunkcounter = 1
        $jsonout = ""
        ForEach ($chunk in $chunkarray) {
            if ($Count -gt 0) {
                Write-Output "Writing data block $chunkcounter of $Count"
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
        [bool]
        $Hound
    )

    Begin {
        #Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'

        $logo = "
                  ╭━━━╮       ╭╮ ╭━━━╮   ╭╮
                  ┃╭━╮┃       ┃┃ ┃╭━━╯   ┃┃
        ╭━━┳━━━╮  ┃┃ ╰╋━┳━━┳━━┫╰━┫╰━━┳┳━━┫╰━╮
        ┃╭╮┣━━┃┣━━┫┃╭━┫╭┫╭╮┃╭╮┃╭╮┃╭━━╋┫━━┫╭╮┃
        ┃╭╮┃┃━━╋━━┫╰┻━┃┃┃╭╮┃╰╯┃┃┃┃┃  ┃┣━━┃┃┃┃
        ╰╯╰┻━━━╯  ╰━━━┻╯╰╯╰┫╭━┻╯╰┻╯  ╰┻━━┻╯╰╯
                           ┃┃
                           ╰╯
                           
      -- L E T S   S T A R T   F I S H I N G --"

        $date = get-date -f yyyyMMddhhmmss
        $baseUrl = 'https://graph.microsoft.com/beta'
        $mngtUrl = 'https://management.azure.com'
        $outputDirectory = $(Get-Location)

        Get-GraphToken
        $scopes = ($_graphToken.scope) -split " " | Sort-Object
    }
    Process {
        Clear-Host
        Write-Host $logo -ForegroundColor White

        $expiry = Get-Date -UnixTimeSeconds $($_graphToken.expires_on)
        Write-Output "`nToken valid until: '$($expiry)'`n"

        #region Active Directory
        $aadRequestHeader = @{
            "Token"          = ($_graphToken.access_Token | ConvertTo-SecureString -AsPlainText -Force)
            "Authentication" = 'OAuth'
            "Method"         = 'GET'
        }

        Write-Output "Collecting RAW tenant data"
        $organizations      = (Get-GraphRecursive @aadRequestHeader -Url "$baseUrl/organization")
        $users              = (Get-GraphRecursive @aadRequestHeader -Url "$baseUrl/users" -select "id, accountEnabled, businessPhones, city, createdDateTime, creationtype, companyName, country, department, displayname, employeeid, employeeType, givenName, imAddresses, jobTitle, mail, mailNickName, mobilePhone, onPremisesDistinguishedName, officeLocation, onPremisesDomainName, onPremisesImmutableId, onPremisesLastSyncDateTime, onPremisesSecurityIdentifier, onPremisesSamAccountName, onPremisesSyncEnabled, onPremisesUserPrincipalName, passwordPolicies, postalCode, state, streetAddress, surname, usageLocation, userPrincipalName, externalUserState, externalUserStateChangeDateTime, userType, identities, lastPasswordChangeDateTime")
        $groups             = (Get-GraphRecursive @aadRequestHeader -Url "$baseUrl/groups")
        $directoryRoles     = (Get-GraphRecursive @aadRequestHeader -Url "$baseUrl/directoryRoles")
        $applications       = (Get-GraphRecursive @aadRequestHeader -Url "$baseUrl/applications")
        $devices            = (Get-GraphRecursive @aadRequestHeader -ur "$baseUrl/devices")
        $serviceprincipals  = (Get-GraphRecursive @aadRequestHeader -ur "$baseUrl/serviceprincipals")

        $roleMembers = (Get-Members -ArrayObject $directoryRoles -type azrolemembers)

        $organizations      | ConvertTo-Json -Depth 10 | Out-File "$outputDirectory\$date-tenants.json"
        $users              | Get-Chunk -Coll $users -Directory $outputDirectory -type "users" #ConvertTo-Json -Depth 10 | Out-File "$outputDirectory\$date-users.json"
        $groups             | ConvertTo-Json -Depth 10 | Out-File "$outputDirectory\$date-groups.json"
        $directoryRoles     | ConvertTo-Json -Depth 10 | Out-File "$outputDirectory\$date-directoryroles.json"
        $applications       | ConvertTo-Json -Depth 10 | Out-File "$outputDirectory\$date-applications.json"
        $devices            | ConvertTo-Json -Depth 10 | Out-File "$outputDirectory\$date-devices.json"
        $serviceprincipals  | ConvertTo-Json -Depth 10 | Out-File "$outputDirectory\$date-serviceprincipals.json"

        if ($hound) {
            Write-Output "Building AzureHound Export"
            export-data $organizations -type aztenants
            export-data $users -type azusers
            export-data $groups -type azgroups
            export-data $directoryRoles -type azdirectoryroles
            export-data $applications -type azapplicationowners
        }

        Write-Output "Processing 'Role Assignments' "
        Get-Chunk -Type "azglobaladminrights" -Directory $outputDirectory -coll ($roleMembers | Where-Object GroupName -eq "Global Administrator")
        Get-Chunk -Type "azprivroleadminrights" -Directory $outputDirectory -coll ($roleMembers | Where-Object GroupName -eq "Privileged Role Administrator")
        Get-Chunk -Type "azapplicationadmins" -Directory $outputDirectory -coll ($roleMembers | Where-Object GroupName -eq "Application Administrator")


        $groupsArray = @(
            "azgroupmembers"
            "azgroupowners"
        )

        Write-Output "Processing 'Groups Objects' "
        foreach ($grp in $groupsArray) {
            Get-Members -ArrayObject $groups -Type $grp
        }

        $appsArray = @(
            "azapplicationowners"
            "azapplicationtosp"
        )

        Write-Output "Processing 'AAD Applications' "
        foreach ($app in $appsArray) {
            Get-Members -ArrayObject $applications -Type $app
        }

        $deviceArray = @(
            "registeredOwners"
        )
        Get-PasswordResetRights
        if ($scopes -contains "Reports.Read.All") {
            $riskyUsers = Get-GraphRecursive @aadRequestHeader -Url "$baseUrl/reports/credentialUserRegistrationDetails"
            Get-Chunk -Coll $riskyUsers -Directory "$outputDirectory" -Type "azuserswithoutmfa"
        }
    }
    End {}
}