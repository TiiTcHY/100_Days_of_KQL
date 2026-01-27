# Name
- KazakRAT - Staging and Execution from Public Folders

# Description
- Identifies the execution of binaries or scripts from the C:\Users\Public\ directory tree. KazakRAT often places its primary loader or the RAT itself (frequently named client.exe, update.exe, or similar) in this folder to bypass path-based restrictions that might apply to standard user profile folders.

# References
- KazakRAT Threat Research - CtrlAltIntel https://ctrlaltintel.com/threat%20research/KazakRAT/

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- KazakRAT

# MITRE Techniques
- Collection
	- T1074.001 Data Staging: Local Data Staging
- Persistence
	- T1574 Hijack Execution Flow

# Data Sources
- Microsoft Defender for Endpoint
	- DeviceProcessEvents
	- DeviceFileEvents

# Query
```
DeviceProcessEvents
| where FolderPath startswith @"C:\Users\Public\"
| where FileName endswith ".exe" or FileName endswith ".bat" or FileName endswith ".vbs"
| where not(FileName in~ ("OneDriveStandaloneUpdater.exe", "MicrosoftEdgeUpdate.exe")) // Filter common noise if necessary
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine
```