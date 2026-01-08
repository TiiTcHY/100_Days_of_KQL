# Name
- RDP usage / exposure

# Description
- Detects RDP connections — useful for lateral movement and potential external exposure of RDP.

# References
- 

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- 

# MITRE Techniques
- Lateral Movement
	- T1021.001 Remote Desktop Protocol
- Initial Access
	- T1133 External Remote Services

# Data Sources
- Microsoft Defender for Endpoint (MDE)
  - DeviceNetworkEvents

# Query
```
DeviceNetworkEvents
| where RemotePort == 3389
| summarize count() by DeviceName, RemoteIP



```