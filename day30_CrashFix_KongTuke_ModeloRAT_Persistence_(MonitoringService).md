# Name
- KongTuke - ModeloRAT Persistence (MonitoringService)

# Description
- Detects the persistence mechanism for ModeloRAT, a Python-based backdoor used against domain-joined targets. It typically creates a Registry Run key named MonitoringService.

# References
- Dissecting CrashFix: KongTuke's New Toy | Huntress https://www.huntress.com/blog/malicious-browser-extention-crashfix-kongtuke

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- KongTuke (ModeloRAT)
- CrashFix

# MITRE Techniques
- Persistence
	- T1547.001 Boot or Logon Autostart Execution: Registry Run Keys
- Defense Evasion
	- T1036.005 Masquerading: Match Legitimate Name or Location

# Data Sources
- Microsoft Defender for Endpoint
	- DeviceRegistryEvents
	- DeviceProcessEvents

# Query
```
DeviceRegistryEvents
| where RegistryKey has @"Software\Microsoft\Windows\CurrentVersion\Run"
| where RegistryValueName =~ "MonitoringService" 
    or RegistryValueName matches regex @"^(Spotify|Adobe|Discord|Dropbox|OneDrive|Teams)\d+$"
| project Timestamp, DeviceName, AccountName, RegistryValueName, RegistryValueData
```