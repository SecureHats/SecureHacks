<#
.Synopsis
   Helper function that creates a watchlist in Microsoft Sentinel
.DESCRIPTION
   This helper function creates or updates a watchlist in Microsoft Sentinel
.EXAMPLE
   New-MsSentinelWatchlist -WorkspaceName 'MyWorkspace' -Context 'C:\users\securehats\highValueAsset.json'
#>
[CmdletBinding()]
[Alias()]
Param
(
    # Graph access token
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
    [string]$WorkspaceName,

    [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 1)]
    [string]$WatchlistName,

    [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 2)]
    [string]$AliasName,

    [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 3)]
    [string]$itemsSearchKey,

    [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 4)]
    [ValidateScript( { (Test-Path -Path $_) -and ($_.Extension -in '.csv') })]
    [System.IO.FileInfo]$csvFile
)

$context = Get-AzContext

if (!$context) {
    Connect-AzAccount -UseDeviceAuthentication
    $context = Get-AzContext
}

$_context = @{
    'Account'         = $($context.Account)
    'Subscription Id' = $context.Subscription
    'Tenant'          = $context.Tenant
}

$logo = "
     _____                           __  __      __
    / ___/___  _______  __________  / / / /___ _/ / ____
    \__ \/ _ \/ ___/ / / / ___/ _ \/ /_/ / __ `/ __/ ___/
   ___/ /  __/ /__/ /_/ / /  /  __/ __  / /_/ / /_(__  )
  /____/\___/\___/\__,_/_/   \___/_/ /_/\__,_/\__/____/ `n`n"

Clear-Host
Write-Host $logo -ForegroundColor White
Write-Output "Connected to Azure with subscriptionId: $($context.Subscription)`n"

$workspace = Get-AzResource -Name $WorkspaceName -ResourceType 'Microsoft.OperationalInsights/workspaces'

if ($null -ne $workspace) {
    $apiVersion = '?api-version=2021-09-01-preview'
    $baseUri = '{0}/providers/Microsoft.SecurityInsights' -f $workspace.ResourceId
    $watchlist = '{0}/watchlists/{1}{2}' -f $baseUri, $AliasName, $apiVersion
}
else {
    Write-Output "[-] Unable to retrieve log Analytics workspace"
}

Write-Verbose ($_context | ConvertTo-Json)

if ($null -ne $csvFile) {
    try {
        Write-Verbose "[-] Trying to read CSV content"
        $content = Get-Content $csvFile | ConvertFrom-Csv
        if (($content.$itemsSearchKey).count -eq 0) {
            Write-Host "[-] Invalid 'itemsSearchKey' value provided, check the input file for the correct header.`n"
            exit
        }
        else {
            Write-Verbose "[-] Selected CSV file contains $($($content.$itemsSearchKey).count) items"
        }
    }
    catch {
        Write-Error 'Unable to process CSV file'
        exit
    }

    try {
        Write-Verbose "[-] Converting file file content for [$($csvFile.Name)]"
        foreach ($line in [System.IO.File]::ReadLines($csvFile.FullName)) {
            $rawContent += "$line`r`n"
        }
    }
    catch {
        Write-Error "Unable to process file content"
    }
}

#Process csv

$argHash = @{}
$argHash.properties = @{
    displayName    = "$WatchlistName"
    source         = "$($csvFile.Name)"
    description    = "Watchlist from $($csvFile.Extension) content"
    contentType    = 'text/csv'
    itemsSearchKey = $itemsSearchKey
    rawContent     = "$($rawContent)"
    provider       = 'SecureHats'
}

try {
    $result = Invoke-AzRestMethod -Path $watchlist -Method PUT -Payload ($argHash | ConvertTo-Json)
    if ($result.StatusCode -eq 200) {
        Write-Output "[+] Watchlist with alias [$($AliasName)] has been created."
        Write-Output "[+] It can take a while before the results are visible in Log Analytics.`n"
    }
    else {
        Write-Output $result | ConvertFrom-Json
    }
}
catch {
    Write-Verbose $_
    Write-Error "Unable to create watchlist with error code: $($_.Exception.Message)" -ErrorAction Stop
}
Write-Output "[+] Post any feature requests or issues on https://github.com/SecureHats/SecureHacks/issues`n"
