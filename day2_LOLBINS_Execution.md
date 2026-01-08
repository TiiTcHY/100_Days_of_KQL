# Name
- Living-off-the-land binaries (LOLBins)

# Description
- Detects trusted Windows binaries abused to execute attacker code or scripts without dropping new malware.

# References
- LOLBAS project: https://lolbas-project.github.io/

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- 

# MITRE Techniques
- Execution
	- T1218 Signed Binary Proxy Execution
- Defense Evasion
	- T1218 Signed Binary Proxy Execution

# Data Sources
- Microsoft Defender for Endpoint (MDE)
  - DeviceProcessEvents

# Query
```
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("mshta.exe","certutil.exe","rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe","wmic.exe","msiexec.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName


```