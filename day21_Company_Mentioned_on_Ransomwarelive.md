# Name
- Company being mentioned on RansomwareLive as a victim

# Description
- This will do a lookup to RansomwareLive recent victims API and then check the set list to see if your tracked companies exist in the Victim Name or Domain field highlighting a potential ransomware compromise. This can be handy to track 3rd party suppliers.

# References
- https://www.ransomware.live/

# Author
- TiiTcHY/Daniel Whitcombe

# Socials
- LinkedIn: https://www.linkedin.com/in/daniel-whitcombe-551a5b10b/

# Threats
- Ransomware Groups

# MITRE Techniques
- Availability
	- T1486 Data Encrypted for Impact
	- T1657 Financial Theft

# Data Sources
- Microsoft Sentinel (Log Analytics)
	- externaldata() ingestion of HTTP JSON feed

# Query
This will use a set list from Threat Intelligence Watchlists:

```
let keywords =
    (_GetWatchlist('RansomwareTargets')
     | project keyword);

let jsonData =
    externaldata(payload: string)
    [
    "https://api.ransomware.live/v2/recentvictims"
    ]
    with (format="raw");
jsonData
| extend parsed = parse_json(payload)
| mv-expand targets = parsed
| extend
    victim = tostring(targets.victim),
    domain = tostring(targets.domain),
    country = tostring(targets.country),
    screenshot = tostring(targets.screenshot),
    url = tostring(targets.url),
    attackdate = tostring(targets.attackdate),
    discovered = tostring(targets.discovered)
| where victim has_any (keywords)
   or domain has_any (keywords)
| project victim, domain, country, screenshot, url, attackdate, discovered
```

This will use a set list within the analytic:

```
let keywords = dynamic([
    "Company1",
    "Company2",
    "Company3",
    "Company4",
    "Company5"
]);
let jsonData =
    externaldata(payload: string)
    [
    "https://api.ransomware.live/v2/recentvictims"
    ]
    with (format="raw");
jsonData
| extend parsed = parse_json(payload)
| mv-expand targets = parsed
| extend
    victim = tostring(targets.victim),
    domain = tostring(targets.domain),
    country = tostring(targets.country),
    screenshot = tostring(targets.screenshot),
    url = tostring(targets.url),
    attackdate = tostring(targets.attackdate),
    discovered = tostring(targets.discovered)
| where victim has_any (keywords)
   or domain has_any (keywords)
| project victim, domain, country, screenshot, url, attackdate, discovered
```