# Name
- NoName57 DDoS Detection

# Description
- This query retrieves the latest NoName57 targeting data from the public JSON feed at witha.name/data/last.json, parses the targets array, and extracts IP, host, port, HTTP method, and request path information. It then performs a case-insensitive lookup for hosts containing the substring, returning matching indicators for analyst review and enrichment.

# References
- https://witha.name/data/last.json

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- NoName57

# MITRE Techniques
- Reconnaissance
	- T1595 Active Scanning
	- T1596 Seach Open Webistes/Domains
- Command and Control
	- T1071.001 Web Protocols
- Impact
	- T1499 Endpoint Denial of Service
	- T1498 Network Denial of Service


# Data Sources
- Microsoft Sentinel (Log Analytics)
	- externaldata() ingestion of HTTP JSON feed

# Query
```
let jsonData =
externaldata(payload:string)
[
    "https://witha.name/data/last.json"
]
with (format="raw");
jsonData
| extend parsed = parse_json(payload)
| mv-expand targets = parsed.targets
| extend host = tostring(targets.host)
| extend ip = tostring(targets.ip)
| extend path = tostring(targets.path)
| extend port = tostring(targets.port)
| extend method = tostring(targets.method)
| where tolower(host) contains "<KEYWORD>"
| project EventTime = now(), host, ip, path, port, method
```