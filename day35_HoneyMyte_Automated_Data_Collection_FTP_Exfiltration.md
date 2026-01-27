# Name
- HoneyMyte - Automated Data Collection & FTP Exfiltration

# Description
- Identifies the scripting phase where HoneyMyte uses PowerShell or Batch scripts to search for documents, compress them (ZIP/RAR), and upload the archive to an attacker-controlled FTP server. This follows the pattern of the "data theft scripts" mentioned in the report.

# References
- HoneyMyte updates CoolClient and deploys multiple stealers - Securelist https://securelist.com/honeymyte-updates-coolclient-uses-browser-stealers-and-scripts/118664/

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- HoneyMyte (Mustang Panda)

# MITRE Techniques
- Collection
	- T1560 Archive Collected Dat
- Exfiltration
	- T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol (FTP)

# Data Sources
- Microsoft Defender for Endpoint
	- DeviceProcessEvents
	- DeviceNetworkEvents

# Query
```
// Correlation of compression and FTP network connection
let FileCompression = DeviceProcessEvents
| where ProcessCommandLine has_any ("zip", "rar", "7z", "compress-archive")
| where ProcessCommandLine has_any (".doc", ".pdf", ".xls", ".txt")
| project CompressionTime=Timestamp, DeviceName, CompressionCmd = ProcessCommandLine;
DeviceNetworkEvents
| where RemotePort == 21 // FTP
| join kind=inner FileCompression on DeviceName
| where Timestamp > CompressionTime and Timestamp < CompressionTime + 30m
| project Timestamp, DeviceName, CompressionCmd, RemoteIP, RemoteUrl
```