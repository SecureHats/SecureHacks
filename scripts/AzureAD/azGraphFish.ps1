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

    Write-Host "Fetching url $Url"
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
    if ($result.'@odata.nextLink') {
        Get-GraphRecursive -Url $result.'@odata.nextLink' @requestBody
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
            Position = 1)]
        [securestring]$Token,

        # Graph access token
        [Parameter(Mandatory = $false,
            Position = 2)]
        [string]$Method,

        [Parameter(Mandatory = $true,
            Position = 3)]
        [string]$Authentication,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 4)]
        [String] $type
    )

    if ($type -like "*groups*") {
        $graph = 'groups'
    }
    if ($type -like "*role*") {
        $graph = 'directoryRoles'
    }

    if ($type -like "*owners*") {
        $objectType = 'Owner'
    }
    if ($type -like "*members*") {
        $objectType = 'Member'
    }
    if ($type -like "*azglobaladminrights*") {
        $objectType = 'Member'
        $graph = 'directoryRoles'
        $roleTemplateId = '62e90394-69f5-4237-9190-012177145e10'
    }

    if ($type -like "*azprivroleadminrights*") {
        $objectType = 'Member'
        $graph = 'directoryRoles'
        $roleTemplateId = "e8611ab8-c189-46e8-94e1-60213ab1f814"
    }

    $date = get-date -f yyyyMMdd
    $metadata = New-Object System.Collections.ArrayList
    $dataHash = New-Object System.Collections.ArrayList

    if ($roleTemplateId) {
        $uri = "$baseUrl/$graph/roleTemplateId=$($roleTemplateId)/$($objectType)s"
        $accounts = (Get-GraphRecursive -Url $uri @requestBody)

        Write-Output $uri

        foreach ($account in $accounts) {
            $currentItem = [PSCustomObject]@{
                "UserName"          = $account.displayName
                "ObjectType"        = (($account.'@odata.id' -split "\.")[-1])
                "UserID"            = $account.id
                "UserOnPremId"      = $account.securityIdentifier
                "TenantDisplayName" = ($organizations | Where-Object id -eq (($account.'@odata.id' -split "/")[4])).displayName
                "TenantId"          = ($account.'@odata.id' -split "/")[4]
            }
            Write-Output $currentItem
            $null = $dataHash.Add($currentItem)
        }
    }
    else {
        foreach ($item in $ArrayObject) {
            Write-Output "[$($graph): $($item.displayName)]"

            $uri = "$baseUrl/$graph/$($item.id)/$($objectType)s"
            $accounts = (Get-GraphRecursive -Url $uri @requestBody)

            foreach ($account in $accounts) {
                $currentItem = [PSCustomObject]@{
                    GroupName                = $item.displayname
                    GroupID                  = $item.id
                    GroupOnPremID            = $item.securityIdentifier
                    "$($objectType)Name"     = $account.displayName
                    "$($objectType)ID"       = $account.id
                    "$($objectType)Type"     = (($account.'@odata.id' -split "\.")[-1])
                    "$($objectType)OnPremID" = $account.securityIdentifier
                }
                Write-Output $currentItem
                $null = $dataHash.Add($currentItem)
            }
        }
    }

    $json = [ordered]@{}
    $json.add("meta", [ordered]@{
            count   = $dataHash.count
            type    = $type
            version = 4
        })
    $json.add("data", $dataHash)
    $json | ConvertTo-Json | Out-File ".\export\$date-$($type).json"
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

    $date = get-date -f yyyyMMdd
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
            $currentItem | Add-Member -MemberType NoteProperty -Name UserPrincipalName -Value "$($item.userPrincipalName)"
            $currentItem | Add-Member -MemberType NoteProperty -Name TenantId -Value "$($context.tenantId)"
        }

        if ($item.appId) {
            $currentItem | Add-Member -MemberType NoteProperty -Name ServicePrincipalId -Value "$($item.id)"
            $currentItem | Add-Member -MemberType NoteProperty -Name ServicePrincipalType -Value "ServicePrincipal"
        }

        Write-Output $currentItem
        $null = $dataHash.Add($currentItem)
    }
    $json = [ordered]@{}
    $json.add("meta", [ordered]@{
            count   = $dataHash.count
            type    = $type
            version = 4
        })
    $json.add("data", $dataHash)
    $json | ConvertTo-Json | Out-File ".\export\$date-$($type).json"
}

function Connect-Tentant {
    az login | Out-Null #--allow-no-subscriptions | Out-Null

    $logo = "
╱╱╱╱╱╱╱╱╱╱╭━━━╮╱╱╱╱╱╱╱╭╮╱╭━━━╮╱╱╱╭╮
╱╱╱╱╱╱╱╱╱╱┃╭━╮┃╱╱╱╱╱╱╱┃┃╱┃╭━━╯╱╱╱┃┃
╭━━┳━━━╮╱╱┃┃╱╰╋━┳━━┳━━┫╰━┫╰━━┳┳━━┫╰━╮
┃╭╮┣━━┃┣━━┫┃╭━┫╭┫╭╮┃╭╮┃╭╮┃╭━━╋┫━━┫╭╮┃
┃╭╮┃┃━━╋━━┫╰┻━┃┃┃╭╮┃╰╯┃┃┃┃┃╱╱┃┣━━┃┃┃┃
╰╯╰┻━━━╯╱╱╰━━━┻╯╰╯╰┫╭━┻╯╰┻╯╱╱╰┻━━┻╯╰╯
╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱┃┃
╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╰╯"

    Clear-Host
    Write-Host $logo -ForegroundColor White

    #current context
    $context = az account show | ConvertFrom-Json
    Write-Output "`nCurrent Context:" $context

    # https://docs.microsoft.com/en-us/cli/azure/account?view=azure-cli-latest#az_account_get_access_token
    # Collect Access Tokens
    $aadtoken = az account get-access-token --resource-type ms-graph | ConvertFrom-Json
    $azToken = az account get-access-token | ConvertFrom-Json

    #set base uri for graph
    $baseUrl = 'https://graph.microsoft.com/beta'
    $mngtUrl = 'https://management.azure.com'

    $requestBody = @{
        "Token"          = ($aadtoken.accessToken | ConvertTo-SecureString -AsPlainText -Force)
        "Authentication" = 'OAuth'
        "Method"         = 'GET'
    }

    return $requestBody
}

#region AD
#Active Directory
$organizations = (Get-GraphRecursive @requestBody -Url "$baseUrl/organization")
$organizations | ConvertTo-Json -Depth 10 | Out-File ".\export\$date-tenants.json"

$users = (Get-GraphRecursive @requestBody -Url "$baseUrl/users")
$users | ConvertTo-Json -Depth 10 | Out-File ".\export\$date-users.json"

$groups = (Get-GraphRecursive @requestBody -Url "$baseUrl/groups")
$groups | ConvertTo-Json -Depth 10 | Out-File ".\export\$date-groups.json"

$directoryRoles = (Get-GraphRecursive @requestBody -Url "$baseUrl/directoryRoles")
$directoryRoles | ConvertTo-Json -Depth 10 | Out-File ".\export\$date-directoryroles.json"

$applications = (Get-GraphRecursive @requestBody -Url "$baseUrl/applications")
$applications | ConvertTo-Json -Depth 10 | Out-File ".\export\$date-applications.json"

$groupMembers = (Get-Members @requestBody -ArrayObject $groups -Type "azgroupmembers")
$groupOwners = (Get-Members @requestBody -ArrayObject $groups -Type "azgroupowners")

$roleMembers = (Get-Members @requestBody -ArrayObject $directoryRoles -Type "azgroupmembers")
$roleGAMembers = (Get-Members @requestBody -ArrayObject $directoryRoles -Type "azglobaladminrights")
$rolePAMembers = (Get-Members @requestBody -ArrayObject $directoryRoles -Type "azprivroleadminrights")


if ($hound) {
    export-data $organizations -type aztenants
    export-data $users -type azusers
    export-data $groups -type azgroups
    export-data $directoryRoles -type azdirectoryroles
}
#endregion AD

#region Azure
$subscriptions = (Get-GraphRecursive -Url "$mngtUrl/subscriptions" @requestBody -api '2020-01-01')
$subroles = (Get-GraphRecursive -Url "$mngtUrl/subscriptions/$subId/providers/Microsoft.Authorization/roleDefinitions" @requestBody -api '2018-07-01')
$customRoles = $permissions.Properties | Where-Object type -ne 'BuiltInRole'
$subRoleAssignments = (Get-GraphRecursive -Url "$mngtUrl/subscriptions/$subId/providers/Microsoft.Authorization/roleAssignments" @requestBody -api '2020-04-01-preview')

$resourceGroups = (Get-GraphRecursive -Url "$mngtUrl/subscriptions/$subId/resourcegroups" @requestBody -api '2020-01-01')
$rgRoleAssignments = (Get-GraphRecursive -Url "$mngtUrl/subscriptions/$subId/resourceGroups/{resourceGroupName}/providers/Microsoft.Authorization/roleAssignments" @requestBody -api '2020-04-01-preview')
$resourceRoleAssignments = (Get-GraphRecursive -Url "$mngtUrl/subscriptions/$subId/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{parentResourcePath}/{resourceType}/{resourceName}/Microsoft.Authorization/roleAssignments" @requestBody -api '2020-04-01-preview')
#endregion Azure

#Current User Permissions
$permissions = (Get-GraphRecursive -Url "$mngtUrl/subscriptions/$subId/resourcegroups/{resourceGroupName}/providers/Microsoft.Authorization/permissions" @requestBody -api '2018-07-01')

foreach ($directoryRole in $directoryRoles) {
    Write-Output "[Role: $($directoryRole.displayName)]"

    $uri = "$baseUrl/directoryRoles/$($directoryRole.id)/members"
    
    $directoryRoleMembers = (Get-GraphRecursive -Url $uri @requestBody)
    Write-Output $directoryRoleMembers | ConvertTo-Json -Depth 100 | Out-File .\outputs\$($directoryRole.id).json
}



$    = az account get-access-token | ConvertFrom-Json
Write-Host "retrieved token" -ForegroundColor Green
Write-Output $token
# Get Azure Resource Groups
$endpoint = "https://management.azure.com/subscriptions/$($token.subscription)/resourcegroups?api-version=2019-08-01"
$headers = @{}
$headers.Add("Authorization", "$("bearer") " + " " + "$($token.accesstoken)")
$resourceGroups = Invoke-RestMethod -Method Get `
    -Uri $endpoint `
    -Headers $Headers
Write-host "retrieved Resource groups" -ForegroundColor Green
Write-Output $resourceGroups.value.name

$baseUrl = 'https://management.azure.com'
$subs = (Invoke-RestMethod -Uri "$baseUrl/subscriptions?api-version=2020-01-01" -Headers $headers).value

foreach ($sub in $subs) {
    $uri = "https://management.azure.com/subscriptions/$($sub.subscriptionId)/resourcegroups?api-version=2019-08-01"
    (Invoke-RestMethod -Method Get `
            -Uri $endpoint `
            -Headers $Headers).value
}

Get-Assignments -ArrayObject $users @requestBody -objectType azusers