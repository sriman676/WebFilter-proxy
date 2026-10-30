# Threat-feed parser and guard corpus (SPEC_EXT_POLICY P3). Used by unit tests, E-60, PT-10.1, F-14.
Setup: protected domains = localhost, webfilter.local, admin.example. Expected: ACCEPT (entry kept, normalized form shown) or REJECT (line skipped and counted) or FILE_REJECT (whole version refused).
| ID | Format | Input line or condition | Expected |
|---|---|---|---|
| FC-01 | domains_text | `evil.example` | ACCEPT apex + subdomains |
| FC-02 | domains_text | `*.evil.example` | ACCEPT subdomains only |
| FC-03 | domains_text | `com` | REJECT single-label |
| FC-04 | domains_text | `localhost` | REJECT protected |
| FC-05 | domains_text | `webfilter.local` | REJECT protected |
| FC-06 | domains_text | `EVIL.Example.` | ACCEPT as `evil.example` |
| FC-07 | domains_text | `xn--bad-` | REJECT invalid IDNA |
| FC-08 | domains_text | `evil..example` | REJECT empty label |
| FC-09 | hostfile | `127.0.0.1 evil.example` | ACCEPT exact host |
| FC-10 | hostfile | `0.0.0.0 localhost` | REJECT protected |
| FC-11 | hostfile | `::1 ip6-localhost` | REJECT single-label |
| FC-12 | urls_text | `http://evil.example/a.exe` | ACCEPT URL digest |
| FC-13 | urls_text | `http://evil.example/%61.exe` | ACCEPT, digest equals FC-12 |
| FC-14 | urls_text | `ftp://evil.example/x` | REJECT scheme |
| FC-15 | urls_text | `http://user:pw@evil.example/` | REJECT userinfo |
| FC-16 | urls_text | `javascript:alert(1)` | REJECT scheme |
| FC-17 | csv_urlhaus | well-formed row with quoted fields and an http URL | ACCEPT URL digest |
| FC-18 | csv_urlhaus | row with an embedded newline inside a quoted field | REJECT row |
| FC-19 | ips_text | `203.0.113.7` | ACCEPT |
| FC-20 | ips_text | `10.0.0.1` | REJECT private |
| FC-21 | ips_text | `203.0.113.0/24` | ACCEPT CIDR |
| FC-22 | ips_text | `0.0.0.0/0` | REJECT overbroad |
| FC-23 | any | line longer than 4096 bytes | REJECT line |
| FC-24 | any | line containing a NUL byte | REJECT line |
| FC-25 | any | UTF-8 BOM at file start, CRLF endings | ACCEPT lines normally |
| FC-26 | any | more than max_entries valid lines | FILE_REJECT |
| FC-27 | any | previous version 1000 entries, new version 400 | FILE_REJECT (sanity guard) unless forced |
| FC-28 | any | previous version 1000 entries, new version 2500 | FILE_REJECT (sanity guard) unless forced |
| FC-29 | any | first ever load of 400 entries | ACCEPT (no previous version) |
| FC-30 | any | more than 50 percent of lines invalid | FILE_REJECT |
