# Name
- HoneyMyte - CoolClient Side-Loading

# Description
- Detects the side-loading pattern used by HoneyMyte where a legitimate binary (frequently VLC Media Player) is renamed to googleupdate.exe and used to load a malicious libvlc.dll. This loader then reads encrypted payload files named loader.ja and goopdate.ja

# References
- HoneyMyte updates CoolClient and deploys multiple stealers - Securelist https://securelist.com/honeymyte-updates-coolclient-uses-browser-stealers-and-scripts/118664/

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- HoneyMyte (Mustang Panda)
- CoolClient

# MITRE Techniques
- Persistence
	- T1574.002 DLL Side-Loading
- Defense Evasion
	- T1036.003 Masquerading: Rename System Utilities

# Data Sources
- Microsoft Defender for Endpoint
	- DeviceProcessEvents
	- DeviceFileEvents
	- DeviceImageLoadEvents

# Query
```
DeviceImageLoadEvents
| where FileName =~ "libvlc.dll"
| where InitiatingProcessFileName =~ "googleupdate.exe"
| join kind=inner (
    DeviceFileEvents
    | where FileName in~ ("loader.ja", "goopdate.ja", "time.sig")
) on DeviceId
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, FolderPath, SHA256
```