# Name
- Failed logons by user

# Description
- Identifies users with high failed authentication attempts — useful for brute-force and password-spray detection.

# References
- 

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- 

# MITRE Techniques
- Credential Access
	- T1110 Brute Force
- Initial Access
	- T1078 Valid Accounts

# Data Sources
- Microsoft Defender for Endpoint (MDE)
  - SigninLogs

# Query
```
SigninLogs
| where ResultType != 0
| summarize FailedLogons=count() by UserPrincipalName
| top 20 by FailedLogons
```