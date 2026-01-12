# Name
- Encoded PowerShell Launcher from LOLBins

# Description
- Identifies encoded or obfuscated PowerShell launched from cmd.exe or mshta.exe, indicating staged execution or download cradles.

# References
- https://clickfix.carsonww.com/domains?limit=50

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- ClickFix / Fake Update campaigns

# MITRE Techniques
- Defense Evasion
	- T1027 Obfuscated/Encoded Commands

- Execution
	- T1059 Command and Scripting Interpreter


# Data Sources
- Microsoft Defender for Endpoint (MDE)
  - DeviceProcessEvents

# Query
```
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("cmd.exe", "mshta.exe")
| where ProcessCommandLine has "powershell"
| where ProcessCommandLine has_any ("-enc", "-encodedcommand")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
```