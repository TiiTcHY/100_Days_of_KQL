# Name
- WScript Executing Temp Folder VBS

# Description
- Detects execution of .vbs files from user Temp folders, a strong indicator of malicious script droppers.

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
	- T1059.005 Visual Basic
- Persistence
	- T1547 Boot or Logon Autostart Execution

# Data Sources
- Microsoft Defender for Endpoint (MDE)
  - DeviceProcessEvents

# Query
```
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "wscript.exe"
| where ProcessCommandLine has_any ("%TEMP%", "\\AppData\\Local\\Temp")
| where ProcessCommandLine has ".vbs"
| project Timestamp, DeviceName, ProcessCommandLine

```