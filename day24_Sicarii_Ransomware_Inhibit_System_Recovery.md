# Name
- Sicarii Ransomware - Inhibit System Recovery (SafeBoot)

# Description
- Detects commands used to disable SafeBoot options via bcdedit.exe. This is a common ransomware tactic used to prevent administrators from recovering the system in a minimal state.

# References
- https://research.checkpoint.com/2026/sicarii-ransomware-truth-vs-myth/

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- Sicarii Ransomware

# MITRE Techniques
- Impact
	- T1490 - Inhibit System Recovery

# Data Sources
- Microsoft Defender for Endpoint
	- DeviceProcessEvents

# Query
```
DeviceProcessEvents
| where FileName =~ "bcdedit.exe"
| where ProcessCommandLine has_any ("safeboot", "deletevalue", "ignoreallfailures")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```