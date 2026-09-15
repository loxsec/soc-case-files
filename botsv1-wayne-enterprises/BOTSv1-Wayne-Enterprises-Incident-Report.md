# Incident Report: Compromise of Wayne Enterprises' Joomla Web Server

**Dataset:** Splunk BOTS v1
**Target:** `imreallynotbatman.com` (192.168.250.70)
**Analyst:** Chibuzor (loxsec)

---

## 1. Executive Summary

An external actor scanned Wayne Enterprises' public Joomla web server, and while their SQL injection and path traversal attempts against the application failed, a separate actor successfully brute-forced the Joomla admin panel's weak credentials (`admin:batman`). The stolen credentials were then used by a second IP to log in, install a malicious file-manager extension as a delivery mechanism, upload a web shell, and execute commands on the host — resulting in confirmed remote code execution and a suspected connection to external command-and-control infrastructure. As of this report, the server is considered compromised and remediation (credential reset, web root integrity restoration, and network egress review) is required immediately.

---

## 2. Incident Timeline

| Time (UTC, 2016-08-10) | Actor IP | Event | Evidence |
|---|---|---|---|
| 21:37:14 – 21:37:57 | 40.80.148.42 | Automated vulnerability scan (Acunetix) — XSS, path traversal, and SQLi payloads sprayed across multiple platform-specific paths (SharePoint, Tomcat, generic root params) | `stream:http`, `src_headers` shows Acunetix Web Vulnerability Scanner user agent |
| 21:42:40 – 21:51:21 | 40.80.148.42 | Path traversal attempts against `win.ini` via Joomla's `catid` and `tmpl` parameters — all attempts failed (3 distinct false-positive response patterns identified and ruled out) | `stream:http`, `dest_content` inspection |
| 21:42:40 – 21:46:23 | 40.80.148.42 | Blind SQL injection attempts against Joomla search component (`catid` parameter, `sleep()`/`pg_sleep()` payloads) — response timing showed no correlation with injected sleep values; several requests returned HTTP 500 | `stream:http`, `duration` field analysis |
| 21:46:33 | 23.22.63.114 | Dictionary brute-force against `/joomla/administrator/index.php` succeeds — valid credential `admin:batman` confirmed | `stream:http`, `com_login` POST, `form_data` |
| 21:48:05 | 40.80.148.42 | Second actor logs into the Joomla admin panel using the harvested credential (92 seconds after brute-force success) | `stream:http`, `com_login` POST, `status=303` |
| 21:50:31 | 40.80.148.42 | Malicious PHP payload installed via Joomla's legitimate `com_installer` extension-install feature — delivery mechanism for further file access | `stream:http`, `install_package=<?php...` |
| 21:51:36+ | 40.80.148.42 | Newly installed `com_extplorer` file-manager extension used to browse the server filesystem | `stream:http`, `action=getdircontents` |
| 21:52:47 | 40.80.148.42 | Web shell `3791.exe` uploaded to the Joomla web root via `com_extplorer` | Suricata `fileinfo` event, `filename: 3791.exe` |
| 21:56:18 | — (host: 192.168.250.70) | `cmd.exe` spawns `3791.exe` from `C:\inetpub\wwwroot\joomla\`, running as `NT AUTHORITY\IUSR` — confirmed remote code execution | Sysmon EventID=1, `ParentImage=cmd.exe`, `Image=3791.exe` |
| 22:06:21 | 192.168.250.70 → 23.22.63.114 | First outbound connection to port 1337 on the attacker's brute-force IP — likely initial callback from the newly executed web shell | `stream:http`, `dest_port=1337` |
| 22:13:46 | 192.168.250.70 → 23.22.63.114 | Outbound HTTP request on port 1337 to `prankglassinebracket.jumpingcrab.com`, retrieving `poisonivy-is-coming-for-you-batman.jpeg` — suspected Poison Ivy RAT payload delivered over a disguised, dynamic-DNS-hosted channel | `stream:http`, non-standard port, dynamic DNS domain, malware-referencing filename |

*Note: only two outbound connections to this destination were observed, roughly 7.5 minutes apart. This is consistent with one-time payload staging/retrieval rather than sustained periodic beaconing — a longer observation window would be needed to confirm ongoing C2 activity.*

---

## 3. The Investigation (Deep Dive)

### 3.1 Hypothesis vs. Evidence

| Hypothesis | Test | Result |
|---|---|---|
| Path traversal on `win.ini` was the initial access vector | Checked `dest_content` and `http_content_type` on every `status=200` hit for `win.ini` | **Disproven.** Every apparent success was a false positive: an unrelated OpenSearch XML response, a Joomla search page that swallowed the payload as inert text, and an empty-body response from a second injection point (`tmpl` parameter). No real file content was ever returned. |
| Blind SQL injection on the Joomla search component succeeded | Converted `duration` (microseconds) to seconds and compared against each request's injected `sleep()`/`pg_sleep()` value | **Disproven.** Response times clustered around 1–12 seconds with no proportional relationship to the injected sleep value (e.g., `sleep(0)` took longer than `sleep(4)`). Several attempts returned HTTP 500, consistent with malformed/failed query execution rather than successful injection. |
| HTTP 200 + large response size indicates a successful exploit | Reasoned through the mechanics of each attack class (SQLi is blind by design; path traversal and file reads are not) | **Refined.** Response-size anomalies are a valid indicator only for attacks that return content directly (e.g., path traversal). They are structurally meaningless for blind SQLi, which produces no visible response difference. |
| The `admin:batman` login by 40.80.148.42 was itself a brute-force success | Checked whether `status=303` differed between failed and successful login attempts | **Corrected mid-investigation.** All login attempts — failed and successful — returned `303`, so status code alone does not indicate success on this login form. Success was instead confirmed by the *subsequent* authenticated actions (`com_installer`, `com_extplorer`) that followed the `admin:batman` attempt, which never occurred after any of the other credentials were tried. |

### 3.2 SPL Queries Used

**Identify the attacker's IP:**
```spl
index="botsv1" "imreallynotbatman.com"
| stats count sum(bytes_in) as bytes_in, sum(bytes_out) as bytes_out by src_ip, dest_ip
| eval total_bytes = bytes_in + bytes_out
| table src_ip, dest_ip, total_bytes, count
```

**Determine scan scope:**
```spl
index="botsv1" src_ip="40.80.148.42" status="200"
| stats count, sum(bytes) as total_data_transferred, values(http_method) as methods by uri_path
| sort - count
```

**Find the vulnerability point (injection payload search):**
```spl
index="botsv1" src_ip="40.80.148.42" sourcetype="stream:http"
| regex uri_query="(?i)(union\s+select|select.*from|or\s+1=1|<script|\.\./\.\./|etc/passwd|cmd\.exe|base64_decode)"
| table _time, src_ip, dest_ip, uri_path, uri_query, form_data, status
| sort _time
```

**Validate path traversal (content-body confirmation, not just status code):**
```spl
index=botsv1 sourcetype=stream:http src_ip="40.80.148.42" uri_path="*win.ini*" status=200
| where NOT match(dest_content, "OpenSearchDescription") AND NOT match(dest_content, "(?i)<!DOCTYPE html")
| table _time, uri_query, http_content_type, bytes_out, dest_content
| sort _time
```

**Validate blind SQLi (timing correlation check):**
```spl
index=botsv1 sourcetype=stream:http src_ip="40.80.148.42" uri_path="*component/search*"
| regex uri_query="sleep\(\d+\)"
| table _time, uri_query, status, duration
| sort _time
```

**Brute-force identification and credential correlation:**
```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri_path="*administrator*"
| rex field=form_data "passwd=(?<pass>\w+)"
| stats count by src_ip, pass
```

**Confirm successful login (via subsequent authenticated activity, not status code):**
```spl
index=botsv1 sourcetype=stream:http src_ip="40.80.148.42" http_method=POST uri_path="administrator/index.php"
| table _time, uri_path, status, uri_query, form_data
| sort _time
```

**Track the web shell upload (Suricata file tracking):**
```spl
index=botsv1 http_method=POST dest_ip="192.168.250.70" filename="3791.exe"
```

**Correlate to endpoint execution (Sysmon pivot):**
```spl
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 CommandLine="*3791.exe*"
```

**Detect C2 beaconing (outbound connections from the victim host):**
```spl
index=botsv1 sourcetype=stream:http src_ip="192.168.250.70"
| stats count by dest_ip, dest_port
| sort -count
```

---

## 4. Adversary Playbook (MITRE ATT&CK Map)

| Tactic | Technique | Evidence |
|---|---|---|
| Reconnaissance | Active Scanning ([T1595](https://attack.mitre.org/techniques/T1595)) | Acunetix scan across multiple paths and platforms |
| Credential Access | Brute Force ([T1110](https://attack.mitre.org/techniques/T1110)) | Dictionary attack against `com_login` from 23.22.63.114 |
| Initial Access | Valid Accounts ([T1078](https://attack.mitre.org/techniques/T1078)) | 40.80.148.42 logs in with the harvested `admin:batman` credential — no application exploit succeeded |
| Persistence | Web Shell ([T1505.003](https://attack.mitre.org/techniques/T1505/003)) | `3791.exe` uploaded to Joomla web root via `com_extplorer` |
| Discovery | File and Directory Discovery ([T1083](https://attack.mitre.org/techniques/T1083)) | `com_extplorer` `getdircontents` browsing |
| Execution | Command and Scripting Interpreter ([T1059](https://attack.mitre.org/techniques/T1059)) | `cmd.exe` spawns `3791.exe`, running as `IUSR` |
| Command and Control | Ingress Tool Transfer ([T1105](https://attack.mitre.org/techniques/T1105)) | Two outbound connections (22:06:21, 22:13:46) to a dynamic-DNS domain on a non-standard port (1337), retrieving `poisonivy-is-coming-for-you-batman.jpeg`. Only two connections were observed, so this is mapped as one-time tool transfer rather than sustained beaconing (T1071), which would require a longer, more regular connection pattern to confirm. |

**Note on deviation from initial hypothesis:** the investigation initially assumed the attack chain would follow Scan → Exploit → Web Shell (per the standard playbook template). The evidence instead showed Scan → Failed Exploitation Attempts → Credential Brute-Force → Valid Account Login → Web Shell. Initial access is mapped to **T1078 (Valid Accounts)**, not T1190 (Exploit Public-Facing Application), because no attempted exploit against the application actually succeeded.

---

## 5. Defensive Recommendations

**1. Detect web shell uploads at the file-system layer.**
Deploy File Integrity Monitoring (FIM) to alert on the creation of any executable file (`.exe`, unexpected `.php`, `.asp`, `.jsp`) within web-accessible directories (e.g., `wwwroot`, `htdocs`). A web root should only ever contain the application's own static and script files — an executable appearing there has effectively no legitimate explanation. Complement this with a WAF/IPS rule blocking executable file types on admin upload endpoints (`com_extplorer`, `com_installer`).

**2. Harden the web server to prevent process execution.**
The compromised process ran as `NT AUTHORITY\IUSR` — the IIS anonymous/application pool identity. This account should never have execute permissions on `cmd.exe`, `powershell.exe`, or any shell interpreter. Recommended controls:
- Deny execute permission on shell binaries for the web server's service account via NTFS ACLs.
- Separate writable upload directories from executable directories so uploaded content can never be executed in place.
- Run the application pool with least privilege, without write access to its own code directories during normal operation.

**3. Close the logging gaps identified during this investigation.**
- **File-transfer visibility:** `stream:http` alone did not reliably surface the exact upload event — Suricata's `fileinfo` event type was needed to confirm timing. Ensure file-transfer tracking (IDS-based or dedicated FIM) is in place for all web-facing hosts.
- **Endpoint process telemetry:** Sysmon (EventID 1) was essential to confirm actual code execution; without it, the web shell upload would have been visible but its execution would not.
- **DNS logging:** the C2 domain (`jumpingcrab.com`, a dynamic DNS provider) would likely have been visible in DNS query logs before the HTTP connection occurred. `stream:dns` should be reviewed as an early-warning layer for this class of C2 infrastructure.
- **Egress filtering:** a proxy or firewall enforcing domain-reputation/category filtering, and blocking outbound connections to non-standard ports (e.g., 1337) and known dynamic-DNS domains, would likely have prevented the payload retrieval even after every other control failed.

**4. Enforce credential hygiene on the Joomla admin panel.**
The root cause enabling this entire chain was a weak, dictionary-guessable administrator password (`batman`). Enforce strong password policy, rate-limit or lock out repeated failed logins against `com_login`, and consider MFA on the admin panel given its direct path to full remote code execution.
