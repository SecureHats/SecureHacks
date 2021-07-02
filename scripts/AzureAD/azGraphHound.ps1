<#
.Synopsis
   Helper function that gets stuff from Microsoft Graph and requests all pages recursively
.DESCRIPTION
   Helper function that gets stuff from Microsoft Graph and requests all pages recursively
.EXAMPLE
   Get-GraphRequestRecursive -Url 'https://graph.microsoft.com/v1.0/groups?$filter=isAssignableToRole eq true' -AccessToken $AccessToken
.EXAMPLE
   Get-GraphRequestRecursive -Url "https://graph.microsoft.com/v1.0/groups/<guid>/members?`$select=id,displayName,userPrincipalName,onPremisesDistinguishedName,onPremisesImmutableId" -AccessToken $AccessToken
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

function Get-Assignments {
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

        # Graph url
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            Position = 5)]
        [String] $Select,

        # Graph url
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 4)]
        [String] $objectType
    )

    foreach ($object in $ArrayObject) {
        Write-Output "[group: $($object.displayName)]"

        $uri = "$baseUrl/groups/$($object.id)/members"
        Write-Output $uri

        $groupOwners = (Get-GraphRecursive -Url $uri @requestBody -select $Select)
        $groupOwners | ConvertTo-Json -Depth 100 | Out-File .\export\$($objectType).json
        pause
    }
}

function export-data {
    [CmdletBinding()]
    [Alias()]
    Param
    (
        [Parameter(Mandatory = $true,
            Position = 0)]
        $dataObject,

        [Parameter(Mandatory = $true,
            Position = 1)]
        $type
    )

    $date = get-date -f yyyyMMddhhmmss
    $metaData = New-Object System.Collections.ArrayList
    $dataHash = New-Object System.Collections.ArrayList

    $metaData.Add([ordered]@{
            count   = $dataObject.count
            type    = $type
            version = 4
        }) | Out-Null

    foreach ($item in $dataObject) {
        $currentItem = [PSCustomObject]@{
            DisplayName                  = $item.displayname
            UserPrincipalName            = $item.UserPrincipalName
            OnPremisesSecurityIdentifier = $item.OnPremisesSecurityIdentifier
            ObjectId                     = $item.id
            TenantId                     = $organizations.id
        }
        Write-Output $currentItem
        $null = $dataHash.Add($currentItem)
    }
    $json = [ordered]@{}
    $json.add("meta", [ordered]@{
        count   = $dataObject.count
        type    = $type
        version = 4
    })
    $json.add("data", $dataHash)
    $json | ConvertTo-Json | Out-File ".\export\$date-$($type).json"
}

az login #--allow-no-subscriptions | Out-Null


$logo = "
╱╱╱╱╱╱╱╱╱╱╭━━━╮╱╱╱╱╱╱╱╭╮╱╭━━━╮╱╱╱╭╮
╱╱╱╱╱╱╱╱╱╱┃╭━╮┃╱╱╱╱╱╱╱┃┃╱┃╭━━╯╱╱╱┃┃
╭━━┳━━━╮╱╱┃┃╱╰╋━┳━━┳━━┫╰━┫╰━━┳┳━━┫╰━╮
┃╭╮┣━━┃┣━━┫┃╭━┫╭┫╭╮┃╭╮┃╭╮┃╭━━╋┫━━┫╭╮┃
┃╭╮┃┃━━╋━━┫╰┻━┃┃┃╭╮┃╰╯┃┃┃┃┃╱╱┃┣━━┃┃┃┃
╰╯╰┻━━━╯╱╱╰━━━┻╯╰╯╰┫╭━┻╯╰┻╯╱╱╰┻━━┻╯╰╯
╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱┃┃
╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╰╯"
Write-Output $logo

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

#Active Directory
$organizations  = (Get-GraphRecursive -Url "$baseUrl/organization" @requestBody)
$users          = (Get-GraphRecursive -Url "$baseUrl/users" @requestBody)
$groups         = (Get-GraphRecursive -Url "$baseUrl/groups" @requestBody)
$directoryRoles = (Get-GraphRecursive -Url "$baseUrl/directoryRoles" @requestBody)
$applications   = (Get-GraphRecursive -Url "$baseUrl/applications" @requestBody)

$roleMembers    = (Get-ObjectMembers -Url "$baseUrl/groups" @requestBody -ArrayObject $directoryRoles)

#Azure
$subscriptions = (Get-GraphRecursive -Url "$mngtUrl/subscriptions" @requestBody -api '2020-01-01')
$subroles = (Get-GraphRecursive -Url "$mngtUrl/subscriptions/$subId/providers/Microsoft.Authorization/roleDefinitions" @requestBody -api '2018-07-01')
$customRoles = $permissions.Properties | Where-Object type -ne 'BuiltInRole'
$subRoleAssignments = (Get-GraphRecursive -Url "$mngtUrl/subscriptions/$subId/providers/Microsoft.Authorization/roleAssignments" @requestBody -api '2020-04-01-preview')

$resourceGroups = (Get-GraphRecursive -Url "$mngtUrl/subscriptions/$subId/resourcegroups" @requestBody -api '2020-01-01')
$rgRoleAssignments = (Get-GraphRecursive -Url "$mngtUrl/subscriptions/$subId/resourceGroups/{resourceGroupName}/providers/Microsoft.Authorization/roleAssignments" @requestBody -api '2020-04-01-preview')
$resourceRoleAssignments = (Get-GraphRecursive -Url "$mngtUrl/subscriptions/$subId/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{parentResourcePath}/{resourceType}/{resourceName}/Microsoft.Authorization/roleAssignments" @requestBody -api '2020-04-01-preview')

#Current User Permissions
$permissions = (Get-GraphRecursive -Url "$mngtUrl/subscriptions/$subId/resourcegroups/{resourceGroupName}/providers/Microsoft.Authorization/permissions" @requestBody -api '2018-07-01')

foreach ($directoryRole in $directoryRoles) {
    Write-Output "[Role: $($directoryRole.displayName)]"

    $uri = "$baseUrl/directoryRoles/$($directoryRole.id)/members"
    
    $directoryRoleMembers = (Get-GraphRecursive -Url $uri @requestBody)
    Write-Output $directoryRoleMembers | ConvertTo-Json -Depth 100 | Out-File .\outputs\$($directoryRole.id).json
}

foreach ($group in $groups) {
    Write-Output "[group: $($group.displayName)]"

    $uri = "$baseUrl/groups/$($group.id)/owners"

    $groupOwners = (Get-GraphRecursive -Url $uri @requestBody)
    Write-Output $groupOwners | ConvertTo-Json -Depth 100 #| Out-File .\outputs\groupOwners\$($group.id).json
}

$token = az account get-access-token | ConvertFrom-Json
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