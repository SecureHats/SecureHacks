Param(
    [Parameter(Mandatory = $False,
        Position = 0)]
    [array]$UserList = "",

    [Parameter(Mandatory = $False,
        Position = 1)]
    [array]$Passwords = "",

    [Parameter(Mandatory = $False,
        Position = 3)]
    [string]$OutFile = "",

    [Parameter(Mandatory = $False,
        Position = 4)]
    [switch]$Force
)

$logo = '   
                                         ╓╓╓╖╖╖╖╖╓╓╓┌                              
         └└ ╙╙╙╩╦╖╖┌                 ╒╓╬╬╬╬╬╫╬╬╬╬╬╬╬╬╬╬╬╬╦╥╥╖╬╬╬╖                   
                   └╙╙┬╦╖╓╓┌┌  ╓╓╓╓╦╦╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╫╬╜╬╬╬╖                
                          └└╙╙╙╙╙└└   ╟╬╬╬╬╬╫╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╖             
                                      ╬╙╨╨╩╬╬╬╬╩╩╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╩╩╨╬╨╩╙
                                       ╙╙└          ╙╘┘      └╙╙╙╙

                                       
                -- L E T S   S T A R T   R A T T I N G --
'

Clear-Host
Write-Host $logo -ForegroundColor Green

$constants = Get-Content "constants.json" | ConvertFrom-Json
$mngtUrl = 'https://management.azure.com'

$ErrorActionPreference = 'silentlycontinue'
$usernames = $UserList | Sort-Object { Get-Random }
$currenttime = Get-Date
$count = $Usernames.count
$dataHash = New-Object System.Collections.ArrayList
$script:fullresults = @()

if ($PasswordList) {
    $Passwords = Get-Content $PasswordList
}
Write-Host -ForegroundColor "yellow" ("[*] There are " + $count + " total users to spray.")
Write-Host -ForegroundColor "yellow" "[*] Current date and time: $currenttime"

# Setting up the web request

    # If we get a 200 response code it's a valid cred
        
    $currentItem = [PSCustomObject]@{
        "username"    = $requestParams.Body.username
        "password"    = "$requestParams.Body.password"
        "agent"       = $agent
        "endpoint"    = $requestParams.Body.resource
        "ErrorMsg"    = ((($ErrMsg.ErrorRecord | ConvertFrom-Json).error_description) -split '\n')[0]
    }
    
    $null = $dataHash.Add($currentItem)


#region subscriptions 
$subscriptions = (Get-GraphRecursive @aadRequestHeader -api '2020-01-01' -Url "$mngtUrl/subscriptions")
#endregion subscriptions


#region Virtual Machine
foreach ($sub in $subscriptions) {
    $virtualMachines += Get-Resource -provider 'Microsoft.Compute/virtualMachines' -subscriptionId $sub.subscriptionId
}

foreach ($vm in $virtualMachines) {
    $IaaSAntimalwareExtension += $vm | Where-Object {$_.resources.id -notlike "*IaaSAntimalware*" }
}
    $networkInterfaces = (Get-Resource -provider 'Microsoft.Network/networkInterfaces' -subscriptionId 'dfa4746a-4647-4d96-8384-a681b8f0dfeb')

    foreach ($nic in $networkInterfaces) {
        Write-Host "[+] Processing $($nic.name)" -ForegroundColor Yellow
        #validate if NSG assigned
        if ($nic.properties.ipConfigurations.properties.publicIPAddress.id) {
            $publicIp += $nic.properties.VirtualMachine.id
        }
        if (-not($nic.properties.NetworkSecurityGroup)) {
            $nsgMissing += $nic.properties.VirtualMachine.id
        } else {
            $networkSecurityGroup = Get-Resource -provider $nic.properties.NetworkSecurityGroup.id
            Write-Host "      Fetched NSG $($networkSecurityGroup.name)"
            $securityRules = $networkSecurityGroup.properties.securityRules 
            Write-Host "      Fetched [$($securityRules.count)] Rules for [$($networkSecurityGroup.name)]"
            foreach ($rule in $securityRules) {
                Write-Host "      Evaluate Rule [$($rule.name)]"
                if ($Rule.properties.access -eq 'Allow' -and $securityRules.properties.sourceAddressPrefix -eq '*') {
                    $nsgVulnerable += $networkSecurityGroup.properties.networkInterfaces.id 
                }
            }
        } 
    }

#endregion Virtual Machine
