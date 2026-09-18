BOTS v1 Investigation
Compromise of a Public-Facing Joomla Server

A SOC-analyst-style incident investigation built on the Splunk Boss of the SOC (BOTS) v1 dataset. Instead of treating it as a CTF answer key, this project is written up as a full incident response engagement: hypotheses tested against raw log evidence, dead ends documented, and findings mapped to MITRE ATT&CK.

Summary

An external actor scanned Wayne Enterprises' public Joomla web server and attempted SQL injection and path traversal against it — both failed. A separate IP then brute-forced the Joomla admin panel's weak password (admin:batman) and handed the working credential off to a second IP, which logged in, installed a malicious file-manager extension, uploaded a web shell (3791.exe), and executed it under the web server's own service account. The compromised host was then observed retrieving a suspected Poison Ivy RAT payload from an external, dynamic-DNS-hosted domain on a non-standard port.

Notable finding: the standard BOTS v1 assumption is that SQL injection or path traversal was the initial access vector. Both were tested directly against the raw HTTP response bodies and response timing, not just status codes, and both were disproven. The real entry point was a brute-forced credential passed between two separate attacker IPs before any exploitation attempt began.

Timeline (highlights)
Time (UTC)	Event
21:37	Automated vulnerability scan begins (Acunetix)
21:46	Brute-force from a second IP finds valid credential admin:batman
21:48	Tracked attacker IP logs in using the harvested credential
21:50–21:52	Malicious extension installed, used to upload web shell 3791.exe
21:56	cmd.exe executes 3791.exe — confirmed remote code execution
22:06–22:13	Outbound connection retrieves suspected Poison Ivy RAT payload

Full timeline, evidence, and SPL queries: BOTSv1-Wayne-Enterprises-Incident-Report.md

Skills Demonstrated
Writing and iterating on SPL queries to test specific hypotheses, not just retrieve data
Validating findings against raw response content and timing, rather than trusting status codes alone
Pivoting across log sources (stream:http → Suricata fileinfo → Sysmon process-creation) to follow one event from delivery to execution
Correcting an initial hypothesis when the evidence didn't support it, and documenting why
Mapping confirmed findings to MITRE ATT&CK tactics and techniques
Producing detection and hardening recommendations tied directly to the evidence found
Log Sources / Tools Used
Splunk (SPL)
stream:http (Splunk Stream)
Suricata fileinfo events
Sysmon (EventID=1 — process creation)
Dataset: Splunk BOTS v1
