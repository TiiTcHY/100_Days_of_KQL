# Name
- TheGentlemen_KnownFilesAndHostArtifacts

# Description
- Detects the SHA-256 hashes, filenames, and host artifacts published in both reports, including EtherRAT, TukTuk, Sliver, Go reverse shells, and runtime/configuration files.

# References
- https://thedfirreport.com/2026/05/11/flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware/
- https://hunt.io/blog/the-gentlemen-etherrat-ethereum-smart-contract-c2

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- The Gentlemen ransomware affiliate activity
- EtherRAT
- TukTuk
- Sliver
- Go-based reverse shells

# MITRE Techniques
- MITRE ATT&CK Enterprise
  - T1105 - Ingress Tool Transfer
  - T1059.007 - JavaScript
  - T1547.001 - Registry Run Keys / Startup Folder
  - T1070 - Indicator Removal on Host

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceFileEvents

# Query
```kusto
DeviceFileEvents
// Limit the scan before matching hashes, names, and paths
| where Timestamp >= ago(30d)
// Match published SHA-256 indicators or high-value host artifacts
| where SHA256 in~ (
        "D9487FDC097F770E5661F9E5DEE130068CB179D33716ABFF1A21C8CB901F25A6",
        "8C2665ADF8BFAB65463F2A9BD1B7BB0231DE3F5C1E6A2E51479E44AAAC2E7BF0",
        "4142D5EFD4EA2ABAB77F2F0A917610E2FF976BF9E19D7AD1E9156ECCDC5412DB",
        "2D4B4BB18B8445E49EEDA571982874403BEFCECF78266E3D405F6529D98BEE46",
        "19021E53B9929FDF4B7D0E0707434D56BB73C1A9B7403C8837B44D1C417198DC",
        "1795EACD2C58894CCDD6BE8854FE6456C3B069A3A873432343B57B475B256AEE",
        "EE6807A8ABFABCED22EE026E178A28DA64D13CC3408E224394FF6E5782FB9E1D",
        "F659681525DEBDA69FE0865B2B27A42F684B1FDA66AA7398E80B84CC765C73C7",
        "7567994310A9576B1F98DC672ECFA038F1D65084315F59E3883F9B6F24000073",
        "73955566338ADFFB423C3B7608792963080DA780E8B7B2C2CD6B6B0CEF6F217F",
        "86881B8E9D197AC2F734792DE48D5DFAEBE7CAFB6E35D49C5DD7FE6EB697230E",
        "F609621698EAAD8C4683750FE8BD0E242349BE3EEA408DA593151FF877ED8AB6",
        "FB94688ED37DFCB985A8A4D720230E5150956E1788D579B0A54B53A153FD2F2E",
        "C7A80576FBD25057435652788591D13998DA272EDF627FC29D296684CEFC50E5",
        "BD61C2880920BBFB86C12DF439DD1CA0258A10E532433698FD029AEF2A5B33F2",
        "F4C87A1DF04274B7497CBF9A4619B946C915CF5210B6E2EAA2FEE1629F4FF196",
        "756C2096F54C5497110C9D854625C3ED592873E566D532077CD7ADB4D10D4ADD"
    )
    or FileName in~ ("RAMMap.msi", "MVnVmUYj.cmd", "A7Pnj975bl.cfg", "v72HYLU3OpRBznc.ini", "cons_c1.0.1.msi", "cons_1.0.1.msi", "jEdb5ROX.cmd", "YUGKag9mvNKWylo.bin", "jlfYWzAkN99jpGu.xml", "BDQbS2lZ6u.bak", "task_39.ps1", "slv_beacon_sc.bin", "svchost_upd.exe", "svchost_update.exe", "ws_3srv.exe")
    or (FileName in~ ("svchost.log", ".node_bot_id") and FolderPath startswith @"C:\Users\" and FolderPath contains @"\AppData\Roaming\")
    or FolderPath contains @"\AppData\Local\MicrosoftSltt\"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, FileSize, SHA1, SHA256, FileOriginUrl, FileOriginIP, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
```
