# Name
- DNS / URL queries to risky TLDs

# Description
- Surface suspicious connections including Tor (.onion) or low-reputation TLDs frequently abused by threat actors.

# References
- 

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- 

# MITRE Techniques
- Command and Control
	- T1071 Application Layer Protocol
	- T1090.003 Proxy: Multi-hop Proxy

# Data Sources
- Microsoft Defender for Endpoint (MDE)
  - DeviceNetworkEvents

# Query
```
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any (".onion", ".top", ".xyz")
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName


```