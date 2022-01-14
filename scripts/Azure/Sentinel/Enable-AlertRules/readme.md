![logo](https://github.com/SecureHats/Sentinel-playground/blob/main/media/sh-banners.png)

# Enable Alert Rules

This script can be used to automatically create and enable detection rules based on the built-in Alert Rules templates in Microsoft Sentinel.
To use this script, you have to loaded the function in PowerShell by dot sourcing it. 

```powershell
  . 'C:\Users\AzureKid\Repos\SecureHats\SecureHacks\Enable-AlertRules\Enable-AlertRules.ps1'
```

## Usage

The function has 2 required parameters, and one optional parameter, which is recommended to use.
When the <dataconnectors> parameter is left empty, all alert rules will be tried to create.
This will probably cause some errors due to missing tables in the Log Analytics workspace

### ResourceGroupName
- The name of the resource group that contains the Log Analytics workspace

### WorkspaceName
- The name of the Log Analytics workspace

### Dataconnectors
- Name of the data connectors to create the detection rules for.
- The DataConnectors has tab completion and can have multiple values.

```powershell
Enable-AlertRules `
  -ResourceGroupName <Name of ResourceGroup> `
  -WorkspaceName <Name of WorkSpace> `
  -DataConnectors <Array of data connectors>
```
  
## Description
  
The Function will first collect all available alert rules templates based on the provided data connectors.
Once the collection is build, the function will try to create a new detection rule from each template.

> NOTE: The function will currently not validate if the detection rule already exists, causing duplication of rules when the function is run multiple times.
 
![image](https://user-images.githubusercontent.com/40334679/149479582-6abecccb-28e9-42a8-aa9f-dc851b1d59bf.png)
  
 ## Logging
 The logfile will be created in the user profile folder.
 In the event of an (un)expected error, a logfile will be generated containing the:
 - Alert rule name
 - Error description (from the API)
 - Tactic
 - Technique
  
  ![image](https://user-images.githubusercontent.com/40334679/149480053-670e2dde-3607-4329-937a-adcc71026787.png)
  
## In Development
  
  - [ ] Logfile location parameter
  - [ ] Staging mode to only validate rules without creating
  - [ ] Gap analysis of detection rules
  - [ ] Detect existing rules
  - [ ] Reporting to Markdown file

 > This function will later be a part of a PowerShell module.
