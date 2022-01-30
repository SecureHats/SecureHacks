![logo](https://github.com/SecureHats/Sentinel-playground/blob/main/media/sh-banners.png)

# Enable Alert Rules

This script can be used to automatically create and enable detection rules based on the built-in Alert Rules templates in Microsoft Sentinel.
To use this script, you have to loaded the function in PowerShell by dot sourcing it. 

```powershell
  . 'C:\Users\AzureKid\Repos\SecureHats\SecureHacks\Enable-AlertRules\Enable-AlertRules.ps1'
```

## Usage

The function has 2 required parameters, and 4 optional parameter.
When the <dataconnectors> parameter is left empty or no watchlist is selected, all available alert rules will be tried to create.
>NOTE This will probably cause some errors due to missing tables in the Log Analytics workspace.

### ResourceGroupName

- The name of the resource group that contains the Log Analytics workspace

### WorkspaceName

- The name of the Log Analytics workspace

## Options

### -UseWatchList

- When the switch is set the default Microsoft Sentinel watchlist ```ActiveConnectors``` will be used.
- The function will look for all connectors that has the ```Enabled``` flag set to ```TRUE``` in the watchlist.

> Before first use this watchlist needs to be created in Microsoft Sentinel [ActiveConnectors.csv](https://raw.githubusercontent.com/SecureHats/SecureHacks/main/scripts/Azure/Sentinel/Enable-AlertRules/dataconnectors.csv)

```powershell
Enable-AlertRules `
  -ResourceGroupName <Name of ResourceGroup> `
  -WorkspaceName <Name of WorkSpace> `
  -UseWatchList
```

### WatchlistName

- The name of a custom watchlist

> When using a custom watchlist the switch ```-UseWatchlist``` needs to be set
>- **NOTE:** This script will look for the _'Watchlist Alias'_ name. **_The name of the watchlist Alias is Case Sensitive_**
>- An example for the watchlist can be found here: [ActiveConnectors.csv](https://raw.githubusercontent.com/SecureHats/SecureHacks/main/scripts/Azure/Sentinel/Enable-AlertRules/dataconnectors.csv)

```powershell
Enable-AlertRules `
  -ResourceGroupName <Name of ResourceGroup> `
  -WorkspaceName <Name of Workspace> `
  -UseWatchList `
  -WatchlistName <myWatchlist>
```

### -Override

- Create a duplicate analytics rule if it already exists.
- The function will add the ```[COPY]``` tag to the *new* rule.
> 
```powershell
Enable-AlertRules `
  -ResourceGroupName <Name of ResourceGroup> `
  -WorkspaceName <Name of Workspace> `
  -UseWatchList `
  -Override
```

  ![image](https://user-images.githubusercontent.com/40334679/149841146-b1587335-7cc8-4114-b3c7-9e80c3037ae2.png)

### LogFileLocation

- Foldername for the logfile. By default the %UserProfile% path will be used.
- If the folder does not exists, it will be created by the function.

```powershell
Enable-AlertRules `
  -ResourceGroupName <Name of ResourceGroup> `
  -WorkspaceName <Name of WorkSpace> `
  -UseWatchList `
  -LogFileLocation <Path of the Log Folder>
```

### Dataconnectors

- Name of the data connectors to create the detection rules for.
- The DataConnectors parameter has tab completion and can have multiple values.

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

  - [x] Logfile location parameter
  - [ ] Staging mode to only validate rules without creating
  - [ ] Gap analysis of detection rules
  - [x] Detect existing rules
  - [ ] Reporting to Markdown file

 > This function will later be a part of a PowerShell module.
