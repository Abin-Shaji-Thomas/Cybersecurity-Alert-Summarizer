# Questions and NLP Lab texts

## Ask-tab questions (verified)

Each question was asked through the API and through the UI after uploading the file. The answers below are what the
app returned, shortened where marked "…". The intent in brackets is the rule that answered it; the supporting alerts
under each answer come from TF-IDF retrieval.

### 01_web_recon_scan.json
| Question | App's answer |
|---|---|
| Which IP attacked the server? | [ips] Source IPs with suspicious alerts (level >= 5): **172.19.131.174 (338)**, 192.168.230.122 (13), 172.19.130.4 (9), … |
| Which hosts did 172.19.131.174 attack? | [hosts] 172.19.131.174 attacked: intranet-server, vpn, webserver, cloud-share, internal-share, mail. |
| When did the attack start? | [time] The attack-phase activity starts at **2022-01-24 03:56:47 UTC** and ends at 03:58:14 UTC. Phases in order: service_scans, wpscan, dirb. |
| Which MITRE techniques were seen? | [mitre] T1595.002 (12), T1021.004 (10), T1055 (8), T1190 (3), T1083 (2). Tactics: Reconnaissance, Lateral Movement, Defense Evasion, … |

### synthetic_02_ssh_bruteforce.json
| Question | App's answer |
|---|---|
| Which IP attacked the server? | [ips] **203.0.113.45 (64)**. |
| Which users were targeted? | [users] oracle (8), ftpuser (8), root (6), admin (6), test (6), ubuntu (6), postgres (6), guest (6) and 2 more. |
| How many failed logins were there? | [count] **22 alerts** match (fail, login): sshd: authentication failed (18), sshd: brute force … Authentication failed (4). *(The 42 "non-existent user" alerts say "Attempt to login", not "fail", so the keyword count leaves them out.)* |
| Did the attacker log in successfully? | [success] **No**: no alert from the suspicious source(s) reports a successful login, session or command. |

### 03_suspicious_dns_tls.json
| Question | App's answer |
|---|---|
| Which source IPs look suspicious? | [ips] **10.70.32.4 (18)**, 172.24.249.224 (8), 151.101.1.194 (2), … and 2 more. |
| Which ports were targeted? | [ports] **443 (24), 53 (3)**, then client ports (56028, 53548, …) and 4 more. |
| When did the activity start? | [time] The activity starts at 2022-01-27 18:31:12 UTC and ends at 2022-01-28 06:47:52 UTC. Phases in order: normal. |
| Which hosts were targeted? | [hosts] 172.27.180.4 (28), 172.24.249.224 (13). |

### 04_multi_stage_attack.json
| Question | App's answer |
|---|---|
| When did the attack start? | [time] The attack-phase activity starts at **2022-01-29 14:38:38 UTC** and ends at 15:05:01 UTC. Phases in order: service_scans, wpscan, dirb, cracking. *(Only alerts of level >= 5 are used; the privilege-escalation alerts are level 3–4.)* |
| Which hosts did 172.24.249.224 attack? | [hosts] 172.24.249.224 attacked: **intranet-server**. |
| Which MITRE techniques were seen? | [mitre] T1595.002 (54), T1078 (24), T1055 (14), T1190 (3), **T1548.003 (3)**, T1083 (2), T1021.004 (1). |
| Did the attacker log in successfully? | [success] **Yes**: 7 success alert(s); the first at 2022-01-29 15:20:51 UTC: 'User successfully changed UID' for user **gmarsh** on intranet-server. |

### 05_normal_noise.json
| Question | App's answer |
|---|---|
| Which source IPs look suspicious? | [ips] Source IPs with suspicious alerts (level >= 5): **none**. |
| What is the most severe incident? | [severity] #… Dovecot Authentication Success on mail from 172.19.131.174 **[Medium**, 32 alerts]; then two Low incidents. |
| Which users were seen? | [users] matthew.begum (10), jhall (10), andrea.moss (6), toby.white (5), rebecca.blake (4), shane.watson (3), alyssa.hayes (1). |
| What should I do next? | [action] For the mail-login incident: *Normal mail logins; confirm the volume and source IPs match expected users.* … |

### synthetic_06_bruteforce_then_success.json
| Question | App's answer |
|---|---|
| Did the attacker log in successfully? | [success] **Yes**: 1 success alert; at 2022-03-15 22:42:35 UTC: 'sshd: authentication success' from **198.51.100.23** for user **jhall** on mail. |
| How many failed logins were there? | [count] **33 alerts** match: sshd: authentication failed (30), sshd: brute force … (3). |
| Which IP attacked the server? | [ips] 198.51.100.23 (33). |
| Which users were targeted? | [users] jhall (34). |

### synthetic_07_port_scan_many_hosts.json
| Question | App's answer |
|---|---|
| Which hosts did 198.51.100.77 attack? | [hosts] cloud-share, inet-dns, internal-share, intranet-server, mail, vpn, webserver, inet-firewall (**8 hosts**). |
| Which ports were targeted? | [ports] 21, 22, 23, 25, 53, 80, 110, 139 **and 7 more** (15 ports). |
| Which IP attacked the server? | [ips] 198.51.100.77 (8). *(Only the 8 sshd alerts are level >= 5; the 15 Nmap alerts are level 3.)* |

### synthetic_08_cve_exploit.json
| Question | App's answer |
|---|---|
| Which MITRE techniques were seen? | [mitre] **T1190 (9), T1068 (4)**, T1055 (1), T1083 (1). Tactics: Initial Access (9), Privilege Escalation (5), … |
| Which IP attacked the server? | [ips] 203.0.113.9 (13). |
| What should I do next? | [action] *Patch the software named in the alert (see the CVE), block the source IP and check the host for signs of compromise.* (for both exploit incidents) |
| What is the most severe incident? | [severity] Log4j RCE Attempt (CVE-2021-44228) [Critical, 9 alerts]; Sudo Heap Overflow (CVE-2021-3156) [Critical, 4 alerts]; ClamAV update [Low]. |

### synthetic_09_two_attackers.json
| Question | App's answer |
|---|---|
| Which IP attacked the server? | [ips] **203.0.113.10 (60), 198.51.100.200 (60)**. |
| Which hosts did 203.0.113.10 attack? | [hosts] 203.0.113.10 attacked: **intranet-server**. |
| Which hosts did 198.51.100.200 attack? | [hosts] 198.51.100.200 attacked: **mail**. |
| Did the attacker log in successfully? | [success] **No**: no alert from the suspicious source(s) reports a successful login, session or command. |

## NLP Lab example texts

Paste one into the NLP Lab text box and click **Run through Units I–V**. Outputs below were produced with the bundled
sample (*Use sample data*) as the corpus. Perplexity depends on which analysis is selected as the corpus.

**1. SSH failure alert**
`At 02:10:05, host intranet-server reported 'sshd: authentication failed' for user root from 203.0.113.45 targeting port 22 (level 5).`
- Unit I: masked to `… from <IP> targeting port <PORT> (level <NUM>)`; 18 tokens; bigram perplexity **6.09** (a familiar pattern).
- Unit II: entities intranet-server HOST, sshd PROTOCOL, root USER, 203.0.113.45 IP, 22 PORT; HMM vs spaCy agreement 0.68.
- Unit III: triple (**203.0.113.45, fail, intranet-server:22**); WordNet fail → fail.
- Unit IV: top TF-IDF terms authentication, `<USER>`, sshd, intranet-server.
- Unit V: SRL Agent 203.0.113.45, Action `fail (sshd: authentication failed)`, Patient port 22, Location intranet-server.

**2. Exploit alert with a CVE**
`At 13:20:00, host webserver reported 'Suricata: Alert - ET EXPLOIT Apache log4j RCE Attempt (http ldap) (CVE-2021-44228)' from 203.0.113.9 targeting port 80 (level 10).`
- Unit I: the CVE number is masked to `CVE-<NUM>-<NUM>`; perplexity **19.48** (rarer than alert 1).
- Unit II: **CVE-2021-44228 CVE**, webserver HOST, http / ldap PROTOCOL, 203.0.113.9 IP, 80 PORT. spaCy's own model wrongly tags "Suricata" as PERSON (a good viva example of out-of-domain errors).
- Unit III: triple (203.0.113.9, **attempt**, webserver:80); WordNet attempt → try.
- Unit IV: http, apache, webserver, attempt. Unit V: Action `attempt (…)`, Patient port 80.

**3. Suspicious DNS query**
`At 18:42:46, host 172.27.180.4 reported 'Suricata: Alert - ET INFO DNS Query for Suspicious .ga Domain' from 10.70.32.4 targeting port 53 (level 6).`
- Unit I: perplexity 17.07. Unit II: 172.27.180.4 IP, 10.70.32.4 IP, DNS PROTOCOL, 53 PORT.
- Unit III: triple (10.70.32.4, **query**, 172.27.180.4:53). The action comes from WordNet: the noun "Query" becomes the verb "query".
- Unit IV: top term "suspicious". Unit V: Agent 10.70.32.4, Action `query (…)`, Patient port 53.

**4. Free-text analyst note (two sentences)**
`Attacker 172.24.249.224 used wpscan and dirb against intranet-server on port 80. Later the user gmarsh escalated to root with sudo (T1548.003), see CVE-2021-3156.`
- Unit I: **2 sentences** (NLTK Punkt); perplexity **158.7**, because free text is very unlike alert sentences.
- Unit II: 172.24.249.224 IP, **wpscan TOOL, dirb TOOL**, intranet-server HOST, 80 PORT, gmarsh USER, **T1548.003 MITRE_TECHNIQUE, CVE-2021-3156 CVE**.
- Unit III: the triple rules are written for the alert-sentence template, so here they give a weak result (actor –, action "see"). This is a known limitation.
- Unit IV: root, sudo, intranet-server.

**5. Toy-grammar sentence (CKY)**
`the attacker scanned the web server from 10.35.1.4`
- Unit II: the pasted sentence is inside the toy CFG, so the **CKY table is filled for this sentence** and returns
  `(S (NP (Det the) (N attacker)) (VP (V scanned) (NP (NP (Det the) (NOM (N web) (N server))) (PP (P from) (NP 10.35.1.4)))))`.
  (For texts 1–4 the Lab shows the same default sentence, because they are outside the toy grammar.)
- Unit III: triple (10.35.1.4, **scan**, –) and the Chu-Liu/Edmonds MST card. Unit I: perplexity 99.3.
