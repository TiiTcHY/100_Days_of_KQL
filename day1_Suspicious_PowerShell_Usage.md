# Name
- Suspicious PowerShell Usage 

# Description
- Looks for PowerShell being used with encoded commands or making web requests to download files from the internet

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
	- T1059.001 PowerShell

-Command and Control
	– T1105 Ingress Tool Transfer

– Defense Evasion
	- T1027 Obfuscated/Encoded Commands

# Data Sources
- Microsoft Defender for Endpoint (MDE)
  - DeviceProcessEvents

# Query
```
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "-encodedcommand", "iwr", "invoke-webrequest", "wget", "download")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```