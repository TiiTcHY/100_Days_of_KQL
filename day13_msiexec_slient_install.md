# Name
- Msiexec Quiet Remote Install from URL

# Description
- Detects MSI package installation from the internet using quiet or passive mode to avoid user interaction.

# References
- https://clickfix.carsonww.com/domains?limit=50

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- ClickFix / Fake Update campaigns

# MITRE Techniques
– Command and Control
	- T1105 Ingress Tool Transfer

- Execution
	- T1218.007 Msiexec


# Data Sources
- Microsoft Defender for Endpoint (MDE)
  - DeviceProcessEvents

# Query
```
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "msiexec.exe"
| where ProcessCommandLine has_any ("/i", "/package")
| where ProcessCommandLine has_any ("http://", "https://")
| where ProcessCommandLine has_any ("/qn", "/quiet", "/passive")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```