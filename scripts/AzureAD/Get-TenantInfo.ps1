function Get-TenantInfo {
    <#
    .Synopsis
      Get the tenant name based on the tenantid.
    .DESCRIPTION
      This function can be used to request the tenant name based on the Id.
    .PARAMETER TenantId [string]
      Enter the tenant id which looks like a guid
    .EXAMPLE
      This will request the tenant name based on the provided Id
    Get-TenantInfo
      Get-TenantInfo -tenantId 'ad6d77d3-22b1-4e0d-9c70-0419308dbd82'
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$TenantId
    )

    $payload = @{
        Grant_Type    = "client_credentials"
        client_id     = "Request Tenant"
        client_secret = (New-Guid).guid
        scope = 'https://graph.microsoft.com/.default'
    }

    try {
        Write-Verbose "[-] Requesting tenant information"

        $requestHash = @{
            "Uri"           = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
            "Method"        = 'POST'
            "Body"          = $payload
            "ErrorVariable" = 'ErrMsg'
        }
        $graphToken = Invoke-RestMethod @requestHash #-Uri $authUri -Method POST -Body $payload -ErrorVariable ErrMsg

        $script:endDate = (Get-Date).AddSeconds($graphToken.expires_in)
        $script:aadRequestHeader = @{
            "Token"          = ($graphToken.access_token | ConvertTo-SecureString -AsPlainText -Force)
            "Authentication" = $graphToken.token_type
            "Method"         = 'GET'
        }
    }
    catch {
        # The request will generate an error because the cliend_id does not exist.
        # In the error body the tenant name is shown

        $response = ((($ErrMsg.ErrorRecord | ConvertFrom-Json).error_description))
        #return $response
        #Perform the opperation
        $result = [regex]::Match($response, "directory '(.*?)'").Groups[1].Value

        if ($result) {
            return $result
        } else {
            Write-Error "No tenant found with guid [$TenantId]"
        }
    }    
}