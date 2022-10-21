function Get-GraphToken {
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String[]]
        [ValidateSet("MSGraph", "Azure")]
        $Client,    
        [Parameter(Mandatory = $False)]
        [String]
        $Resource = "https://graph.microsoft.com"
        
    )
    
    switch ($Client) {
        "MSGraph" {
            $body = @{
                "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                "resource"  = "https://graph.microsoft.com"
            }
        }
        "Azure" {
            $body = @{
                "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                "resource"  = "https://management.core.windows.net"
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
            $global:_graphToken = Invoke-RestMethod `
                -UseBasicParsing `
                -Method Post `
                -Uri "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0 " `
                -Body $body `
                -ErrorAction SilentlyContinue
        }
        catch {
            $details = $_.ErrorDetails.Message | ConvertFrom-Json
            $continue = $details.error -eq "authorization_pending"
            Write-Output $continue

            if (!$continue) {
                Write-Error $details.error_description
                return
            }
        }
        if($_graphToken)
        {
            $global:aadRequestHeader = @{
                "Token"          = ($_graphToken.access_token | ConvertTo-SecureString -AsPlainText -Force)
                "Authentication" = 'OAuth'
                "Method"         = 'GET'
            }

            break
        }
    }
}

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

    if ($api) {
        $url = '{0}?api-version={1}' -f $Url, $Api
        if ($filter) {
            $url = '{0}&`filter={1}' -f $Url, $filter
        }
    }
    if ($select) {
        $url = '{0}&`$select={1}' -f $url, "$select"
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
            if ($resultCount -gt 1000) {
                Write-Host "Processing $($resultCount) items"
            }
        }
    }
    catch {
        # Nothing to process
    }
}

function Get-Resource {
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [String]$subscriptionId,

        [Parameter(Mandatory = $true)]
        [String]$provider
    )

    if ($subscriptionId) {
        $uri = '{0}/subscriptions/{1}/providers/{2}' -f $mngtUrl, $subscriptionId, $provider
        $resources = (Get-GraphRecursive @aadRequestHeader -api '2021-04-01' -Url $uri)
    } else {
        $uri = '{0}{1}?api-version=2022-01-01' -f $mngtUrl, $provider
        $resources = Invoke-RestMethod @aadRequestHeader -Uri $uri
    }

    return $resources
}
