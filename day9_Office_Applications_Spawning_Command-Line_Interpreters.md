# Name
- Office Applications Spawning Command-Line Interpreters

# Description
- Detects Microsoft Office applications spawning command-line or scripting interpreters. This behavior is commonly associated with malicious Office documents leveraging macros, embedded scripts, or DDE to execute arbitrary code.

# References
- 

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- Emotet
- TrickBot
- QakBot
- Dridex
- IcedID
- BazaLoader


# MITRE Techniques
- Execution
	- T1059 Command and Scripting Interpreter
	- T1204.002 — User Execution: Malicious File

# Data Sources
- Microsoft Defender for Endpoint (MDE)
  - DeviceProcessEvents

# Query
```
DeviceProcessEvents
| where InitiatingProcessFileName in~ (
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "onenote.exe",
    "visio.exe",
    "msaccess.exe"
)
| where FileName in~ (
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "wmic.exe",
    "schtasks.exe",
    "bitsadmin.exe"
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessCommandLine
| order by Timestamp desc
```