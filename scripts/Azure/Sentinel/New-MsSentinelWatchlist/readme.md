![logo](https://github.com/SecureHats/Sentinel-playground/blob/main/media/sh-banners.png)

# New-MsSentinelWatchlist

This script can be used to create and update watchlists in Microsoft Sentinel through PowerShell.

## Usage

The script has 5 required parameters.
>NOTE After creating the watchlist it can take some time until the watchlist results are visible.

### WorkspaceName

- The name of the Log Analytics workspace

### WatchlistName

- Displayname of the whatchlist in Microsoft Sentinel.
>- **NOTE:** This script will look for the _'Watchlist Alias'_ name. **_The name of the watchlist Alias is Case Sensitive_**

> Before first use this watchlist needs to be created in Microsoft Sentinel [ActiveConnectors.csv](https://raw.githubusercontent.com/SecureHats/SecureHacks/main/scripts/Azure/Sentinel/Enable-AlertRules/dataconnectors.csv)

### AliasName

- The Alias name of the Microsoft Sentinel watchlist.
- This is the name that will be used in the KQL query when retrieving data from the watchlist.

![image](https://user-images.githubusercontent.com/40334679/154118632-c0127d6c-3205-469a-9f62-8f2772e10993.png)

### itemsSearchKey
- The search key is used to optimize query performance when using watchlists for joins with other data. For example, enable a column with IP addresses to be the designated SearchKey field, then use this field as the key field when joining to other event data by IP address.
> NOTE During deployment the script will validate if the column used as the 'itemsSearchKey' exists in the csv file.

### csvFile

- The path of the CSV file to create the watchlist items.

```powershell
New-MsSentinelWatchlist `
  -WorkspaceName <Name of WorkSpace> `
  -WatchlistName <displayName of watchlist> `
  -AliasName <Alias of the watchlist>
  -itemsSearchKey <Indexed column for filtering>
  -csvFile <C:\example.csv>
```

> After running the script it can take several minutes before the items show up in the watchlist
> 
![image](https://user-images.githubusercontent.com/40334679/154126341-3169af83-4653-4438-9983-3e21f3cb7cef.png)

![image](https://user-images.githubusercontent.com/40334679/154126844-3f150b74-edf7-4525-ad30-732ae1cbf473.png)


## In Development

  - [ ] Support for multiple filetypes (txt, json, yml)
  - [ ] Create empty watchlist
  - [ ] Remove items from watchlist
  - [ ] Add items to watchlist

 > This function will later be a part of a PowerShell module.
