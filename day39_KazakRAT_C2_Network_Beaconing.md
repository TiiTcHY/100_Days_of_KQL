# Name
- KazakRAT - C2 Network Beaconing

# Description
- Monitors for network connections initiated by suspicious processes (like those running from C:\Users\Public) to external IP addresses over non-standard ports or common HTTP/S ports. KazakRAT uses specific check-in patterns to receive instructions from the attacker.

# References
- KazakRAT Threat Research - CtrlAltIntel https://ctrlaltintel.com/threat%20research/KazakRAT/

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- KazakRAT

# MITRE Techniques
- Command and Control
	- T1071.001 Application Layer Protocol: Web Protocols

# Data Sources
- Microsoft Defender for Endpoint
	- DeviceNetworkEvents

# Query
```
DeviceNetworkEvents
| where InitiatingProcessFolderPath startswith @"C:\Users\Public\"
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
```