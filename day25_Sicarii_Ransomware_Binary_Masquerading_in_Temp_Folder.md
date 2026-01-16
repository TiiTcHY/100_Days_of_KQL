# Name
- Sicarii Ransomware - Binary Masquerading in Temp Folder

# Description
- Detects the specific behavior of Sicarii ransomware copying itself to the user's temporary directory and renaming itself using the svchost_{random}.exe pattern.

# References
- https://research.checkpoint.com/2026/sicarii-ransomware-truth-vs-myth/

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- Sicarii Ransomware

# MITRE Techniques
- Defense Evasion
	- T1036.003 - Masquerading: Rename System Utilities
- Execution
	- T1204.002 - User Execution: Malicious File
- Collection
	- T1074.001 - Data Staging: Local Data Staging



# Data Sources
- Microsoft Defender for Endpoint
	- DeviceFileEvents
	- DeviceProcessEvents

# Query
```
DeviceProcessEvents
| where FolderPath has @"\AppData\Local\Temp"
| where FileName matches regex @"(?i)svchost_[a-zA-Z0-9]+\.exe"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```