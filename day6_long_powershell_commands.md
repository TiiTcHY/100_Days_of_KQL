# Name
- Long PowerShell command lines

# Description
- Flags unusually long PowerShell commands, often containing obfuscated Base64 content.

# References
- 

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- 

# MITRE Techniques
- Defense Evasion
	- T1027 Obfuscated/Encoded Commands
- Execution
	- T1059.001 PowerShell

# Data Sources
- Microsoft Defender for Endpoint (MDE)
  - DeviceProcessEvents

# Query
```
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| extend CmdLength = strlen(ProcessCommandLine)
| where CmdLength > 500
| project Timestamp, DeviceName, CmdLength, ProcessCommandLine


```