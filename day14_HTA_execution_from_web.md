# Name
- Remote HTA Execution via mshta.exe

# Description
- Detects execution of remote HTML Application files using mshta.exe, common in fake browser update and social engineering campaigns.

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
	- T1218.005 – Mshta

# Data Sources
- Microsoft Defender for Endpoint (MDE)
  - DeviceProcessEvents

# Query
```
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "mshta.exe"
| where ProcessCommandLine matches regex @"https?://"
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine
```