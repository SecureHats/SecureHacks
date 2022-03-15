[CmdletBinding()]
param (
    [Parameter(Mandatory = $True)]
    [guid]$UserObjectId,

    [Parameter(Mandatory = $True)]
    [guid]$roleDefinitionId
)

function Get-GraphToken {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [ValidateSet('AzureAd', 'Azure')]
        [string]$resource = 'AzureAd'
    )

    Begin {
        try {
            az version | out-Null
        }
        catch {
            Write-Output "Azure CLI is required to run az-GraphFish. Press any key to continue (except the power button)"
            Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi; Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'; Remove-Item .\AzureCLI.msi
        }
    }
    Process {
        try {
            # https://docs.microsoft.com/en-us/cli/azure/account?view=azure-cli-latest#az_account_get_access_token
            if ($resource -eq "AzureAD") {
                Write-Output "Grabbing Azure AD Token"
                $_graphToken = (az account get-access-token --resource-type ms-graph | ConvertFrom-Json)
            }
            else {
                Write-Output "Grabbing Azure Resource Token"
                $_graphToken = (az account get-access-token | ConvertFrom-Json)
            }

            $script:graphToken = $_graphToken
            $script:aadRequestHeader = @{
                "Token"          = ($_graphToken.accessToken | ConvertTo-SecureString -AsPlainText -Force)
                "Authentication" = 'OAuth'
                "Method"         = 'GET'
            }
        }
        catch {
            Write-Error $Error #"Unable to process graph token request"
        }
    }
}

$payload = @{
    "@odata.type"      = "#microsoft.graph.unifiedRoleAssignment"
    "roleDefinitionId" = $roleDefinitionId
    "principalId"      = $UserObjectId
    "directoryScopeId" = "/"
}

$uri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments'


Invoke-RestMethod -Uri $uri @aadRequestHeader -Method 'POST' -Body ($payload | ConvertTo-Json)
