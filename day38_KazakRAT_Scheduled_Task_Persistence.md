# Name
- KazakRAT - Scheduled Task Persistence

# Description
- Detects the creation of scheduled tasks that point to binaries located in the Public or AppData directories. KazakRAT uses schtasks.exe to ensure the RAT restarts upon system boot or user login.

# References
- KazakRAT Threat Research - CtrlAltIntel https://ctrlaltintel.com/threat%20research/KazakRAT/

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- KazakRAT

# MITRE Techniques
- Persistence
	- T1053.005 Scheduled Task/Job: Scheduled Task

# Data Sources
- Microsoft Defender for Endpoint
	- DeviceProcessEvents

# Query
```
DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("C:\\Users\\Public", "AppData\\Roaming")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```