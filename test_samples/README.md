# Test samples

Small, ready-to-upload alert files cut from the **real** AIT-ADS `shaw` scenario (29 January 2022) by
`backend/scripts/make_test_samples.py`. They are raw Wazuh JSON-lines, exactly like the full dataset. Upload them on
the Dashboard (drag & drop, or click the upload box). The numbers below are what the app produced for each file.

| File | Raw alerts → after dedup | What it contains | What the app should show |
|---|---|---|---|
| `login_bruteforce.json` | 558 → 309 | 13:05–13:50 UTC. 10.70.34.215 guesses mail passwords on `collinsbecker-mail`: *PAM: User login failed*, *Dovecot Invalid User Login Attempt*, *Dovecot brute force attack*, *PAM: Multiple failed logins*. There is also normal mail/TLS background traffic. | 7 incidents, 3 High/Critical. Top: **Critical**, *PAM: User login failed … from 10.70.34.215* (44 alerts, **ongoing**, **attempted**). Phase `credential_access` from MITRE T1110 rules (this period is not an attack window in labels.csv, so no scenario is detected). |
| `web_scan_dirb_wpscan.json` | 456 → 451 | 14:38:30–14:39:45 UTC. 172.24.249.224 runs wpscan and dirb against the web server: HTTP 400 floods (every 12th kept), *Suspicious URL access*, *Common web attack*. | Scenario `shaw` detected, phases `wpscan` → `dirb`. 6 incidents, 4 High/Critical. Top: **Critical**, *Multiple web server 400 error codes … from 172.24.249.224*. The host appears as `192.168.188.179`: this small file has no alert that carries that agent's hostname. |
| `suspicious_dns_tls.json` | 771 → 348 | 12:00–12:15 and 14:44–15:06 UTC. DNS queries to `.cloud` domains (Suricata *ET INFO Observed DNS Query to .cloud TLD*) and a long series of malformed TLS traffic (*TLS invalid handshake / record*) from 10.70.32.4. | 11 incidents, 2 High/Critical. Top: *Multiple IDS alerts for same id … from 10.70.32.4* (Critical); TLS incidents of 82 alerts each (Medium); a DNS incident on port 53. |
| `mixed_attack_chain.json` | 791 → 533 | 14:37–15:22 UTC, the whole attack in order: scans → wpscan → dirb → password cracking → privilege escalation (sudo to root by `gmarsh`). Floods are thinned (400 errors every 20th, mail background every 3rd). | Scenario `shaw`, 8 phases on the Timeline in order. 14 incidents, 5 High/Critical. Look for the web-scan incident (Critical) and the *PAM: Login session opened / Successful sudo to ROOT* incident, whose outcome is **succeeded**. |
| `bad_file.txt` | – | Plain text, not JSON. | The upload is rejected with the message *Unsupported file type '.txt'…*; nothing is stored. |

AIT-ADS has **no SSH brute-force attack**, so the brute-force example uses the real password-guessing attack on the mail
server (PAM/Dovecot), which Wazuh flags as "brute force".

Regenerate the files (needs the dataset in `data/raw/`):

```powershell
backend\.venv\Scripts\python backend\scripts\make_test_samples.py
```

## Example questions for the Ask tab

Run on the bundled sample (*Use sample data*), or on `mixed_attack_chain.json` (use 172.24.249.224 there):

1. `Which hosts did 172.19.131.174 attack?`
2. `When did the attack start?`
3. `What MITRE techniques were seen?`
4. `Which ports were targeted?`
5. `Which source IPs look suspicious?`
6. `What should I do next?`

On `login_bruteforce.json`: `How many failed logins were there?`

## Example texts for the NLP Lab

Paste one into the NLP Lab text box and click **Run through Units I–V**:

1. An alert sentence (all units, triple, entities):
   `At 13:12:41, host collinsbecker-mail reported 'PAM: User login failed' for user michael.sutton from 10.70.34.215 (level 5).`
2. A free-text analyst note (sentence segmentation, CVE / MITRE / tool entities):
   `Attacker 172.24.249.224 used wpscan and dirb against intranet-server on port 80. Later the user gmarsh escalated to root with sudo (T1548.003), see CVE-2021-3156.`
3. A sentence inside the toy CKY grammar (CKY table and tree):
   `the attacker scanned the web server from 10.35.1.4`

A raw JSON alert (one line copied from any file above) also works: the Lab converts it to a sentence first.
