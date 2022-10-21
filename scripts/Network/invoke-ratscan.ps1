[CmdletBinding()]
param (
    [Parameter()]
    [switch]$IDPS,

    [Parameter()]
    [switch]$ThreatIntel,

    [Parameter()]
    [switch]$WebCategories
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
Write-Output ""
$endPoints = @()
$threatIndicators = @()

if ($ThreatIntel) {
    Write-Host "[+] Starting Threat Intelligence tests" -ForegroundColor Green
    $articles = (Invoke-RestMethod -UseBasicParsing -Uri "https://ti.defender.microsoft.com/api/articles/").result.count
    Write-Host "    [-] Collecting Public Threat Indicators" -ForegroundColor Green
    $threatIndicators = (Invoke-RestMethod -UseBasicParsing -Uri "https://ti.defender.microsoft.com/api/articles/").result.communityIndicators
    $types = @('url')

    Write-Host "    [-] Preparing endpoint validation" -ForegroundColor Green
    foreach ($ti in $threatIndicators) {
        foreach ($type in $types) {
            $endpoints += ($ti | Where-Object type -in $type).values
        }
    }

    Write-Host "    [-] Querying vulnerable endpoints" -ForegroundColor Green
    foreach ($endpoint in $endPoints) {
        if ($endpoint) {
            try {
                Write-Host "        [-] $endpoint" -ForegroundColor Green
                $null = Invoke-WebRequest -Uri $endpoint -TimeoutSec 15
            }
            catch {
                Write-Information "    [-] Endpoint not available"
            }
        }
    }
} 

if ($IDPS) {
    Write-Host "[+] Starting IDPS tests" -ForegroundColor Green
    $userAgents = @('Mozilla/3.0', 'HaxerMen',, 'xfilesreborn', 'M0zilla')
    foreach ($userAgent in $userAgents) {
        Write-Host "    [-] using Agent [$($userAgent)]...`r" -ForegroundColor Green
        $null = Invoke-RestMethod -Uri http://neverssl.com -UserAgent $userAgent
    }
    
    $null = Invoke-RestMethod -Uri 'https://rb.gy/nnxklz'
    
    Write-Host
    Write-Host "All done! Check your SIEM for alerts using the timestamps [$(Get-Date)]" -ForegroundColor Green
    Write-Host
}
