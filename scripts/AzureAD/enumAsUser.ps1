az login --allow-no-subscriptions

#current context
$context = az account show | ConvertFrom-Json

#https://docs.microsoft.com/en-us/cli/azure/account?view=azure-cli-latest#az_account_get_access_token
$token = az account get-access-token --resource-type ms-graph | ConvertFrom-Json

#set base uri for graph
$baseUri = 'https://graph.microsoft.com/beta/'

$requestBody = @{
    "token"          = ($token.accessToken | ConvertTo-SecureString -AsPlainText -Force)
    "Authentication" = 'OAuth'
    "Method"         = 'GET'
}

$users          = (Invoke-RestMethod "$baseUrl/users" @requestBody)
$groups         = (Invoke-RestMethod "$baseUrl/groups" @requestBody)
$apps           = (Invoke-RestMethod "$baseUrl/applications" @requestBody).value
$directoryRoles = (Invoke-RestMethod "$baseUrl/directoryRoles" @requestBody).value

foreach ($directoryRole in $directoryRoles) {
    Write-Output "[Role: $($directoryRole.displayName)]"
    
    $uri = "$baseUrl/directoryRoles/$($directoryRole.id)/members"
    
    $directoryRoleMembers = (Invoke-RestMethod -Uri $uri @requestBody).value
    Write-Output $directoryRoleMembers
}
