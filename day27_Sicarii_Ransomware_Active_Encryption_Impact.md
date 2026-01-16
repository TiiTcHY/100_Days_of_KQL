# Name
- Sicarii Ransomware - Active Encryption Impact

# Description
- Detects the mass renaming of files to include the .sicarii extension, indicating an active ransomware encryption event.

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
	- T1486 - Data Encrypted for Impact

# Data Sources
- Microsoft Defender for Endpoint
	- DeviceFileEvents

# Query
```
DeviceFileEvents
| where FileName endswith ".sicarii"
| summarize FileCount = count() by DeviceName, bin(Timestamp, 2m)
| where FileCount > 20
| project Timestamp, DeviceName, FileCount
```