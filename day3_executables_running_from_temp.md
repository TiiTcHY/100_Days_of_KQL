# Name
- New executables from user/temp folders

# Description
- Finds executables running from non-standard user locations — common for droppers and payloads.

# References
- 

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- 

# MITRE Techniques
- Execution
	- T1204 User Execution
- Persistence
	- T1547 Autostart Execution
- Initial Access
	- T1566 Phishing
	
# Data Sources
- Microsoft Defender for Endpoint (MDE)
  - DeviceProcessEvents

# Query
```
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FolderPath has_any ("\\Users\\", "\\AppData\\", "\\Temp\\")
| where FileName endswith ".exe"
| project Timestamp, DeviceName, FolderPath, FileName, ProcessCommandLine
```