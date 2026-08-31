Original Alert / Question

Does /var/log/auth.log show a pattern of repeated failed SSH logins followed by a success, consistent with brute-force behaviour — and if so, is it a real attack or a legitimate user struggling to authenticate?

Splunk Free has no native scheduled alerting, so this detection runs as a saved Report against a fail-streak-before-success threshold (fail_streak >= 5 within a 15-minute window).
