# Name
- KongTuke - Finger.exe LOLBin Abuse

# Description
- Detects the "CrashFix" execution chain where the legitimate Windows finger.exe utility is copied to the %TEMP% directory (often renamed as ct.exe)

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
- Defense Evasion
	- T1218 System Binary Proxy Execution (LOLBins)
- Command and Control
	- T1105 Ingress Tool Transfer
- Execution
	- T1059.003 - Windows Command Shell

# Data Sources
- Microsoft Defender for Endpoint
	- DeviceProcessEvents

# Query
```
DeviceProcessEvents
| where (FileName =~ "cmd.exe") 
| where ProcessCommandLine has_all ("System32", "%temp%")
| where ProcessCommandLine has_all ("finger.exe", "ct.exe"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine
```