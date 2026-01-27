# Name
- KazakRAT - Initial Access via Malicious LNK/PowerShell

# Description
- Detects the initial execution phase where an explorer.exe process (user clicking a file) triggers a PowerShell command to download the next stage. KazakRAT frequently uses PowerShell to fetch payloads from remote C2 servers and save them into the C:\Users\Public\ directory.

# References
- KazakRAT Threat Research - CtrlAltIntel https://ctrlaltintel.com/threat%20research/KazakRAT/

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- KazakRAT

# MITRE Techniques
- Execution
	- T1204.001 - User Execution: Malicious Link
	- T1059.001 - PowerShell
- Command and Control
	- T1105 - Ingress Tool Transfer

# Data Sources
- Microsoft Defender for Endpoint
	- DeviceProcessEvents

# Query
```
DeviceProcessEvents
| where InitiatingProcessFileName =~ "explorer.exe"
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("Invoke-WebRequest", "iwr", "curl", "wget")
| where ProcessCommandLine has "C:\\Users\\Public"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
```