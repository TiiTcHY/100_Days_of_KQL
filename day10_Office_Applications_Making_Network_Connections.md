# Name
- Office Applications Initiating Network Connections

# Description
- Detects Microsoft Office applications initiating outbound network connections. While some network activity is expected, malicious documents often abuse Office processes to download additional payloads, communicate with command-and-control (C2) servers, or stage malware during phishing and initial access operations.

# References
- 

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- Emotet
- QakBot
- IcedID
- Dridex
- BazaLoader
- Ursnif
- FormBook
- AgentTesla

# MITRE Techniques
- Command and Control
	- T1105 Ingress Tool Transfer
	- T1071 Application Layer Protocol
- Exfiltration
	- T1041 Exfiltration Over C2 Channel


# Data Sources
- Microsoft Defender for Endpoint (MDE)
  - DeviceNetworkEvents

# Query
```
DeviceNetworkEvents
| where InitiatingProcessFileName in~ (
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "onenote.exe",
    "visio.exe",
    "msaccess.exe"
)
| where RemoteIPType == "Public"
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    RemoteIP,
    RemoteUrl,
    RemotePort,
    Protocol,
    InitiatingProcessCommandLine
| order by Timestamp desc
```