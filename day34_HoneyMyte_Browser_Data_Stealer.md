# Name
- HoneyMyte - Browser Data Stealer

# Description
- Detects one of the three new browser stealer variants used by HoneyMyte. It targets Chromium-based browsers (Chrome, Edge, Brave) to harvest Login Data and Cookies. The rule looks for non-browser processes (like malicious loaders or scripts) accessing these sensitive database files.

# References
- HoneyMyte updates CoolClient and deploys multiple stealers - Securelist https://securelist.com/honeymyte-updates-coolclient-uses-browser-stealers-and-scripts/118664/

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- HoneyMyte (Mustang Panda)

# MITRE Techniques
- Credential Access
	- T1539 Steal Web Session Cookie
	- T1555.003 Credentials from Web Browsers

# Data Sources
- Microsoft Defender for Endpoint
	- DeviceFileEvents

# Query
```
DeviceFileEvents
| where FileName in~ ("Login Data", "Cookies", "Web Data", "History")
| where FolderPath has_any ("Google\\Chrome", "Microsoft\\Edge", "BraveSoftware")
| where not(InitiatingProcessFileName in~ ("chrome.exe", "msedge.exe", "brave.exe", "explorer.exe"))
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, FolderPath, RequestAccountName
```