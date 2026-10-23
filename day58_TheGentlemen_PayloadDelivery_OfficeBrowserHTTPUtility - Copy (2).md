# Name
- TheGentlemen_PayloadDelivery_OfficeBrowserHTTPUtility

# Description
- Identifies curl or certutil launched directly by a listed Microsoft Office application or web browser with an HTTP(S) reference in its command line. This provides a lead for possible payload retrieval; it does not establish a completed download or malicious intent.

# References
- https://socradar.io/blog/inc-gentlemen-ransomware-ai-infrastructure/

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- The Gentlemen

# MITRE Techniques
- Command and Control
	- T1105 - Ingress Tool Transfer

# Data Sources
- DeviceProcessEvents
	- 

# Query
```
DeviceProcessEvents
| where ActionType == "ProcessCreated"
| where FileName in~ ("curl.exe", "certutil.exe")
    or ProcessVersionInfoOriginalFileName in~ ("curl.exe", "certutil.exe")
| where InitiatingProcessFileName in~ (
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "msaccess.exe", "msedge.exe", "chrome.exe", "firefox.exe"
    )
| where ProcessCommandLine contains "http://"
    or ProcessCommandLine contains "https://"
| order by Timestamp desc
| project Timestamp, DeviceId, DeviceName, ReportId,
    AccountDomain, AccountName, AccountSid, FileName, FolderPath,
    ProcessId, ProcessCreationTime, ProcessCommandLine,
    ProcessVersionInfoOriginalFileName, SHA1,
    InitiatingProcessFileName, InitiatingProcessFolderPath,
    InitiatingProcessId, InitiatingProcessCreationTime,
    InitiatingProcessCommandLine, InitiatingProcessParentFileName
```