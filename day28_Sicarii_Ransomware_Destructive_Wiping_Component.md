# Name
- Sicarii Ransomware - Destructive Wiping Component

# Description
- Detects the creation and execution of destruct.bat, a script used by Sicarii to wipe disks and corrupt the bootloader.

# References
- https://research.checkpoint.com/2026/sicarii-ransomware-truth-vs-myth/

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- Sicarii Ransomware

# MITRE Techniques
- Impact
	- T1485 Data Destruction
	- T1491.001 - Defacement: Internal Defacement

# Data Sources
- Microsoft Defender for Endpoint
	- DeviceFileEvents
	- DeviceProcessEvents

# Query
```
DeviceFileEvents
| where FileName =~ "destruct.bat"
| project FileCreationTime=Timestamp, DeviceName, FolderPath, InitiatingProcessFileName
| join kind=inner (
    DeviceProcessEvents 
    | where FileName in~ ("cmd.exe", "cipher.exe", "diskpart.exe")
) on DeviceName
```