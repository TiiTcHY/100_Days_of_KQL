# Name
- Browser-to-LOLBins Execution Chain

# Description
- Detects suspicious process chains where a web browser spawns script engines or administrative tools, strongly indicative of fake update infection.

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
	- T1204 User Execution
- Initial Access
	- T1189 Drive-by Compromise

# Data Sources
- Microsoft Defender for Endpoint (MDE)
  - DeviceProcessEvents

# Query
```
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","iexplore.exe","firefox.exe","brave.exe","opera.exe")
| where FileName in~ ("powershell.exe","cmd.exe","mshta.exe","wscript.exe","msiexec.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
```