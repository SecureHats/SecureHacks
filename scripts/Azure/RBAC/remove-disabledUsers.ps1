<#
# This function will check for all the deactivated accounts for all subscriptions
# And will remove the role assignemnts for the deactivated accounts.
#>
Param($Timer)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$queryResult = Search-AzGraph -Query @'
    securityresources
    | where type == "microsoft.security/assessments"
    | extend source = tostring(properties.resourceDetails.Source)
    | extend resourceId =
        trim(" ", tolower(tostring(case(source =~ "azure", properties.resourceDetails.Id,
                                        source =~ "aws", properties.resourceDetails.AzureResourceId,
                                        source =~ "gcp", properties.resourceDetails.AzureResourceId,
                                        extract("^(.+)/providers/Microsoft.Security/assessments/.+$",1,id)))))
    | extend status = trim(" ", tostring(properties.status.code))
    | extend cause = trim(" ", tostring(properties.status.cause))
    | extend assessmentKey = tostring(name)
    | where assessmentKey == "00c6d40b-e990-6acf-d4f3-471e747a27c4"
'@

Write-Output "Found $($QueryResult.Data.Count) role assignments to be removed."

foreach ($data in $queryResult.Data) {
    $resourceId = $data.ResourceId.Substring(0, $data.ResourceId.IndexOf('/providers/Microsoft.Security/assessments'))
    $objectIdList = $data.properties.AdditionalData.deprecatedAccountsObjectIdList
    $regex = "[^a-zA-Z0-9-]"
    $splitres = $objectIdList -split (',')
    $deprecatedObjectIds = $splitres -replace $regex

    Write-Output "Searching for user to remove on scope '$resourceId'."
    foreach ($objectId in $deprecatedObjectIds) {
        $roleAssignments = Get-AzRoleAssignment -Scope $resourceId | Where-Object { $_.ObjectId -eq $objectId }
        if ($roleAssignments) {
            foreach ($roleAssignment in $roleAssignments) {
                Write-Output "Removing object ID '$objectId' from role definition ID '$($roleAssignment.RoleDefinitionId)'."
                try {
                    Remove-AzRoleAssignment -ObjectId $objectId -RoleDefinitionId $roleAssignment.RoleDefinitionId
                }
                catch {
                    Write-Warning $_.Message
                }
            }
        }
        else {
            Write-Output "Could not find direct role assignment. Getting user from AAD and removing group memberships."

            $resourceURI = "https://graph.microsoft.com/"
            $tokenAuthURI = $env:IDENTITY_ENDPOINT + "?resource=$resourceURI&api-version=2019-08-01"
            $splattedParams = @{
                Method  = 'Get'
                Headers = @{"X-IDENTITY-HEADER" = "$env:IDENTITY_HEADER" }
                Uri     = $tokenAuthURI
            }
            $accessToken = (Invoke-RestMethod @splattedParams).access_token

            $memberURL = "https://graph.microsoft.com/v1.0/users/$objectId/memberOf"
            $groupMemberships = Invoke-RestMethod -Uri $memberURL -Method Get -Headers @{"Authorization" = "Bearer $accessToken" }
            $groupMembershipsToProcess = $groupMemberships.value |
                Where-Object { ($_.'@odata.type' -notlike "#microsoft.graph.directoryRole") -and ($_.groupTypes -notcontains "DynamicMembership") }

            foreach ($groupMembership in $groupMembershipsToProcess) {
                $memberOfGroup = Get-AzADGroupMember -GroupObjectId $groupMembership.id |
                Where-Object { ($_.ObjectType -eq "User") -and ($_.Id -eq $objectId) }

                if ($memberOfGroup) {
                    Write-Output "User '$($memberOfGroup.DisplayName)' is part of group '$($groupMembership.displayName)' and will be removed now from this group."
                    Remove-AzADGroupMember -MemberObjectId $objectId -GroupObjectId $groupMembership.id | Out-Null
                }
            }
        }
    }
}
