# Name
- KongTuke - Victim Profiling & C2 Beaconing

# Description
- Detects the specific network "beacon" used by the malware to profile the victim and sending antivirus status to the C2 server at 199.217.98[.]108.

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
- Discovery
	- T1082 System Information Discovery
- Command and Control
	- T1071.001 Application Layer Protocol: Web Protocols


# Data Sources
- Microsoft Defender for Endpoint
	- DeviceNetworkEvents

# Query
```
DeviceNetworkEvents
| where RemoteIP in ("199.217.98.108", "170.168.103.208", "158.247.252.178")
   or RemoteUrl has_any ("nexsnield.com", "fyvw2oiv.top")
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName
```