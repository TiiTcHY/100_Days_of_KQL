# Name
- Shadow Copy Deletion

# Description
- Adversaries executing this technique aim to prevent recovery from backups by deleting or destroying Windows Volume Shadow Copies and other OS-based recovery data prior to or during ransomware encryption.

# References
- https://media.kasperskycontenthub.com/wp-content/uploads/sites/63/2024/09/16054035/Common-TTPs-of-the-modern-ransomware_low-res.pdf
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-321a
- https://assets.zyrosite.com/mePORKrXBzie3257/redreport2023-picus-A85D3PpkeacpDq05.pdf


# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- LockBit - https://assets.zyrosite.com/mePORKrXBzie3257/redreport2023-picus-A85D3PpkeacpDq05.pdf
- BlackCat - https://www.logpoint.com/wp-content/uploads/2023/04/logpoint-a-comprehensive-guide-to-detect-ransomware.pdf
- Clop - https://media.kasperskycontenthub.com/wp-content/uploads/sites/63/2024/09/16054035/Common-TTPs-of-the-modern-ransomware_low-res.pdf
- Hive Ransomware - https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-321a

# MITRE Techniques
- Impact
	- T1490 Inhibit System Recovery


# Data Sources
- Microsoft Defender for Endpoint (MDE)
  - DeviceProcessEvents

# Query
```
DeviceProcessEvents
| where FileName in~ ("vssadmin.exe","wmic.exe","powershell.exe","pwsh.exe","bcdedit.exe","wbadmin.exe")
| where ProcessCommandLine has_any ("delete shadows", "shadowcopy delete", "delete catalog", "recoveryenabled no")
| project
    Timestamp,
    DeviceName,
    InitiatingProcessAccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    FolderPath
| order by Timestamp desc

```
