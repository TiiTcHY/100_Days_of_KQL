# Name
- PowerShell with Large Base64 Blobs

# Description
- Detects PowerShell command lines that contain large Base64-encoded payloads, commonly used for in-memory stagers, download cradles, and obfuscation.

# References
- https://clickfix.carsonww.com/domains?limit=50

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- ClickFix / Fake Update campaigns

# MITRE Techniques

- Execution
	- T1059.001 PowerShell
- Defense Evasion
	- T1027 Obfuscated/Encoded Commands

# Data Sources
- Microsoft Defender for Endpoint (MDE)
  - DeviceProcessEvents

# Query
```
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine matches regex @"[A-Za-z0-9+/=]{100,}"
| project Timestamp, DeviceName, CmdLength=strlen(ProcessCommandLine), ProcessCommandLine
```