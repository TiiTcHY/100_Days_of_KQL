# Name
- ClickFix Verification Comment In Command

# Description
- Detects execution LOLBins commands being executed with a comment in the command along with a "I am not a robot" as part of the ClickFix verifiction

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
	- T1059 Command and Scripting Interpreter
	- T1059.001 PowerShell
	- T1218.005 Mshta
	- T1204 User Execution
	- T1218.007 Msiexec
	
- Defense Evasion
	- T1027 Obfuscated/Encoded Commands

# Data Sources
- Microsoft Defender for Endpoint (MDE)
  - DeviceProcessEvents

# Query
```
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName has_any ("mshta.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "curl.exe", "msiexec.exe") 
| where ProcessCommandLine contains "#" | where ProcessCommandLine contains "I am not a robot"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```