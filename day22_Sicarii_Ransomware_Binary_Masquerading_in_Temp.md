# Name
- Sicarii Ransomware - Binary Masquerading in Temp

# Description
- Detects the Sicarii ransomware's behavior of copying itself to the %TEMP% directory and renaming itself to a masqueraded system process name (svchost) followed by a random string.

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



# Data Sources
- Microsoft Defender for Endpoint
	- DeviceProcessEvents

# Query
```
DeviceProcessEvents
| where FolderPath has @"\AppData\Local\Temp"
| where FileName matches regex @"svchost_[a-zA-Z0-9]+\.exe"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, AccountName
```