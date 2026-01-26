# Name
- KongTuke - PowerShell Payload Staging in AppData

# Description
- Identifies the second stage of the KongTuke infection where PowerShell is used to download a script (often named script.ps1) to the user's AppData directory and execute it immediately.

# References
- Dissecting CrashFix: KongTuke's New Toy | Huntress https://www.huntress.com/blog/malicious-browser-extention-crashfix-kongtuke

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- KongTuke
- CrashFix

# MITRE Techniques
- Execution
	- T1059.001 Command and Scripting Interpreter: PowerShell
- Command and Control
	- T1105 Ingress Tool Transfer

# Data Sources
- Microsoft Defender for Endpoint
	- DeviceProcessEvents

# Query
```
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_all ("Invoke-WebRequest", "AppData", "script.ps1")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```