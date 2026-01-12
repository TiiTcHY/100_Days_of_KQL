# Name
- PowerShell Download

# Description
- Detects PowerShell processes that both download remote content and execute it, a common pattern for initial loaders and stagers.

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
	- T1059.001 PowerShell

- Command and Control

	- T1105 Ingress Tool Transfer
	
# Data Sources
- Microsoft Defender for Endpoint (MDE)
  - DeviceProcessEvents

# Query
```
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("Invoke-WebRequest", "Invoke-RestMethod", "iwr", "wget")
| where ProcessCommandLine has_any ("Invoke-Expression", "IEX", "Start-Process")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```