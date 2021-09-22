![logo](https://github.com/SecureHats/SecureHacks/blob/main/media/securehats-banner.png)
=========
[![GitHub release](https://img.shields.io/github/release/SecureHats/Sentinel-playground.svg?style=flat-square)](https://github.com/SecureHats/SecureHacks/releases)
[![Maintenance](https://img.shields.io/maintenance/yes/2021.svg?style=flat-square)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)

## Role Assignment Policy

The Azure Policy is used to either audit or deny role assignments in the Azure RBAC model.
When assigning the policy to the selected scope the policy will evaluate if the desginated Azure AD Groups are used to assign role permissions.
This can be useful in cases where privileged roles are directly assigned to identity objects other than groups.

Because the Azure AD GroupId is used this solution is also compatible with _Privileged Access Groups_ through PIM

## Deployment:

## Try on Portal

[![Deploy to Azure](http://azuredeploy.net/deploybutton.png)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/https%3A%2F%2Fraw.githubusercontent.com%2FSecureHats%2FSecureHacks%2Fmain%2Fpolicies%2Fgovernance%2FRoleAssignments%2Fazurepolicy.json)

### Try with PowerShell

````powershell
$definition = New-AzPolicyDefinition -Name "audit-role-assignments" -DisplayName "Audit Privileged Role Assignments" -description "Audit if privileged roles are only assigned to the allowed groups" -Policy 'https://raw.githubusercontent.com/SecureHats/SecureHacks/main/policies/governance/RoleAssignments/azurepolicy.rules.json' -Parameter 'https://raw.githubusercontent.com/SecureHats/SecureHacks/main/policies/governance/RoleAssignments/azurepolicy.parameters.json' -Mode All
$definition
$assignment = New-AzPolicyAssignment -Name <assignmentname> -Scope <scope>  -tagName <tagName> -PolicyDefinition $definition
$assignment 
````

### Try with CLI

````cli
az policy definition create --name 'audit-role-assignments' --display-name 'Audit Privileged Role Assignments' --description 'Audit if privileged roles are only assigned to the allowed groups' --rules 'https://raw.githubusercontent.com/SecureHats/SecureHacks/main/policies/governance/RoleAssignments/azurepolicy.rules.json' --params 'https://raw.githubusercontent.com/SecureHats/SecureHacks/main/policies/governance/RoleAssignments/azurepolicy.parameters.json' --mode All

az policy assignment create --name <assignmentname> --scope <scope> --policy "audit-role-assignments" 
````

## Usage:

### parameters section (Required)
- The objectId of the Azure AD Groups can be found using the [Azure AD Portal Groups section](https://aad.portal.azure.com/#blade/Microsoft_AAD_IAM/GroupsManagementMenuBlade/AllGroups)

![image](https://user-images.githubusercontent.com/72928684/134205967-65c63736-8ac7-48f2-8509-c883dbc45ec5.png)

- The current policy expects a group for _Owners_, _Contributors_, and _User Access Administrators_

 ![image](https://user-images.githubusercontent.com/72928684/134207773-9b0fa1e3-92e5-4aad-ac84-333bf8027ae3.png)

### Non-compliance messages (Optional)

- This section can be used to display a user friendly message when role assignment is denied.

![image](https://user-images.githubusercontent.com/72928684/134207028-a244923e-0cc3-43fe-8ee1-dbb98435671e.png)

![image](https://user-images.githubusercontent.com/72928684/134207510-10043e6a-cd6c-4f05-ae37-1602e29807e6.png)
