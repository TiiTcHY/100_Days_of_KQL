# Name
- Sicarii Ransomware - Multi-Layered Persistence

# Description
- Detects the creation of the WinDefender service, the addition of the SysAdmin local user account, or the modification of Registry Run keys, all used by Sicarii for redundant persistence.

# References
- https://research.checkpoint.com/2026/sicarii-ransomware-truth-vs-myth/

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- Sicarii Ransomware

# MITRE Techniques
-  Persistence
	- T1543.003 - Create or Modify System Process: Windows Service
	- T1136.001 - Create Account: Local Account
	- T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys

# Data Sources
- Microsoft Defender for Endpoint
	- DeviceProcessEvents
	- DeviceRegistryEvents

# Query
```
DeviceProcessEvents
| where (FileName =~ "sc.exe" and ProcessCommandLine has "create" and ProcessCommandLine has "WinDefender")
   or (FileName in~ ("net.exe", "net1.exe") and ProcessCommandLine has "SysAdmin")
   or (ProcessCommandLine has @"Software\Microsoft\Windows\CurrentVersion\Run")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```