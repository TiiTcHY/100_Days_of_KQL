# Name
- TheGentlemen_RemoteAccess_RemoteRegistryRDPTransition

# Description
- Identifies a locally observed RemoteRegistry start request followed within ten minutes by a recorded fDenyTSConnections change from 1 to 0 on the same device. This indicates possible preparation for remote access; it does not prove successful service execution or an RDP session.

# References
- https://socradar.io/blog/inc-gentlemen-ransomware-ai-infrastructure/

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- The Gentlemen

# MITRE Techniques
- Lateral Movement
	- T1021.001 - Remote Services: Remote Desktop Protocol

# Data Sources
- DeviceProcessEvents
- DeviceRegistryEvents

# Query
```
let SequenceWindow = 10m;
let ServiceStartRequests = DeviceProcessEvents
| where ActionType == "ProcessCreated"
| where FileName in~ ("sc.exe", "net.exe", "net1.exe", "powershell.exe", "pwsh.exe")
| where ProcessCommandLine has "RemoteRegistry"
| where (
    FileName in~ ("sc.exe", "net.exe", "net1.exe")
    and ProcessCommandLine matches regex @"(?i)(?:^|[\\/\s""'])(?:sc|net|net1)(?:\.exe)?[""']?\s+start\s+[""']?RemoteRegistry[""']?(?:\s|$)"
    ) or (
    FileName in~ ("powershell.exe", "pwsh.exe")
    and ProcessCommandLine matches regex @"(?i)(?:^|[\s;{""'])Start-Service\s+(?:-Name\s+)?[""']?RemoteRegistry[""']?(?:[\s;""'}]|$)"
    and not(ProcessCommandLine has_any ("ComputerName", "CimSession", "InputObject", "WhatIf"))
    )
| project DeviceId, ServiceRequestTime = Timestamp,
    ServiceRequestReportId = ReportId, ServiceTool = FileName,
    ServiceCommand = ProcessCommandLine, ServiceAccount = AccountName,
    ServiceAccountDomain = AccountDomain,
    ServiceProcessId = ProcessId, ServiceProcessCreationTime = ProcessCreationTime;
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryValueName =~ "fDenyTSConnections"
| where RegistryValueData in~ ("0", "0x0", "0x00000000")
| where PreviousRegistryValueData in~ ("1", "0x1", "0x00000001")
| where RegistryKey endswith @"\Control\Terminal Server"
| where RegistryKey matches regex @"(?i)^(?:HKEY_LOCAL_MACHINE|HKLM)\\SYSTEM\\(?:CurrentControlSet|ControlSet[0-9]{3})\\Control\\Terminal Server$"
| join kind=inner (ServiceStartRequests) on DeviceId
| where ServiceRequestTime <= Timestamp
| where Timestamp <= ServiceRequestTime + SequenceWindow
| summarize arg_max(ServiceRequestTime, *) by DeviceId, Timestamp, ReportId
| extend SequenceDelay = Timestamp - ServiceRequestTime
| order by Timestamp desc
| project Timestamp, DeviceId, DeviceName, ReportId,
    RegistryKey, RegistryValueName, RegistryValueType,
    PreviousRegistryValueData, RegistryValueData,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessAccountDomain, InitiatingProcessAccountName,
    ServiceRequestTime, ServiceRequestReportId, SequenceDelay,
    ServiceTool, ServiceCommand, ServiceAccountDomain, ServiceAccount,
    ServiceProcessId, ServiceProcessCreationTime
```