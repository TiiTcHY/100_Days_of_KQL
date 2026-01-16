# Name
- Sicarii Ransomware - Connectivity Loop Anti-Analysis

# Description
- Identifies the high-frequency internet connectivity check (120 attempts) to Google's generate_204 endpoint, which Sicarii uses to verify network readiness and potentially bypass simple sandbox timeout triggers.

# References
- https://research.checkpoint.com/2026/sicarii-ransomware-truth-vs-myth/

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- Sicarii Ransomware

# MITRE Techniques
- Discovery
	- T1497.001 - Virtualization/Sandbox Evasion: System Checks
	- T1016 - System Network Configuration Discovery

# Data Sources
- Microsoft Defender for Endpoint
	- DeviceNetworkEvents

# Query
```
DeviceNetworkEvents
| where RemoteUrl has "google.com/generate_204"
| summarize ConnectionCount = count() by DeviceName, bin(Timestamp, 5m), RemoteUrl
| where ConnectionCount >= 100 
| project Timestamp, DeviceName, ConnectionCount, RemoteUrl
```