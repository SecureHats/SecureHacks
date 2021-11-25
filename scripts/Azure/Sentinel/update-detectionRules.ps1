

$baseUri = "/subscriptions/${SubscriptionId}/resourceGroups/${ResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${Workspace}"
$templatesUri = "$baseUri/providers/Microsoft.SecurityInsights/alertRuleTemplates?api-version=2021-10-01-preview"

$alertUri = "$baseUri/providers/Microsoft.SecurityInsights/alertRules/"
$alertRulesTemplates = ((Invoke-AzRestMethod -Path "$($templatesUri)" -Method GET).Content | ConvertFrom-Json).value

$AlertRules = $alertRulesTemplates.properties | where-object alertRulesCreatedByTemplateCount -ne 0

foreach ($item in $alertRules) {
    if ($item.kind -eq "Scheduled") {
        foreach ($alert in $alerts) {
            if ($alert.properties.alertRuleTemplateName -in $item.name) {
                $alertUriGuid = $alertUri + $alert.name + '?api-version=2021-10-01-preview'

                $properties = @{
                    queryFrequency        = $item.properties.queryFrequency
                    queryPeriod           = $item.properties.queryPeriod
                    triggerOperator       = $item.properties.triggerOperator
                    triggerThreshold      = $item.properties.triggerThreshold
                    severity              = $item.properties.severity
                    query                 = $item.properties.query
                    entityMappings        = $item.properties.entityMappings
                    templateversion       = $item.properties.version
                    displayName           = $item.properties.displayName
                    description           = $item.properties.description
                    enabled               = $true
                    suppressionDuration   = "PT5H"
                    suppressionEnabled    = $false
                    alertRuleTemplateName = $item.name
                }

                if($item.properties.techniques){
                    $properties.techniques = $item.properties.techniques
                }
                if($item.properties.tactics){
                    $properties.tactics = $item.properties.tactics
                }

                $alertBody = @{}
                $alertBody | Add-Member -NotePropertyName kind -NotePropertyValue $item.kind -Force
                $alertBody | Add-Member -NotePropertyName properties -NotePropertyValue $properties

                try {
                    $tmp = Invoke-AzRestMethod -Path $alertUriGuid -Method PUT -Payload ($alertBody | ConvertTo-Json -Depth 10)
                }
                catch {
                    Write-Verbose $_
                    Write-Error "Unable to create alert rule with error code: $($_.Exception.Message)" -ErrorAction Stop
                }
                break
            }
        }
    }
}
