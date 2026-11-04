# Dataset — AIT Alert Data Set (AIT-ADS)

**Source:** Landauer, M., Skopik, F., Wurzenberger, M. *AIT Alert Data Set (AIT-ADS)*, Zenodo record
[8263181](https://zenodo.org/records/8263181), licence **CC BY 4.0**.
Download with `backend\.venv\Scripts\python backend\scripts\download_data.py` (verifies MD5 `43db6b1f0996e0024befd617706c50e9`).

## Files

| File | Size | Content |
|---|---|---|
| `ait_ads.zip` | 96 MB | 8 scenarios × (`<scenario>_wazuh.json`, `<scenario>_aminer.json`) |
| `labels.csv` | 4 KB | `scenario, attack, start, end` — UNIX start/end time of every attack phase |

Scenario sizes (Wazuh file, unzipped): russellmitchell 45 MB (41,488 alerts), shaw 75 MB (68,539),
wardbeck 97 MB, santos 145 MB, fox 491 MB, harrison 633 MB, wheeler 651 MB, wilson 674 MB.

**Used in this project:** `russellmitchell` and `shaw` (the two smallest) for development and evaluation.
AMiner files are skipped: they are anomaly-detector outputs, not text alerts.

## Format we actually found

The `_wazuh.json` files are **JSON-lines** (one alert object per line). Suricata alerts are inside the same file
(they reach Wazuh from `eve.json` with decoder `json`, and again from `fast.log` with decoder `snort`).

Field paths and how often they occur in russellmitchell (41,488 alerts):

| Our column | Field path(s) in the raw alert | Present in |
|---|---|---|
| timestamp | `@timestamp` (ISO, UTC) | 100 % |
| description | `rule.description` | 100 % |
| level | `rule.level` (Wazuh 0–15; observed 3, 5, 6, 8, 10, 11) | 100 % |
| mitre_id / mitre_tactic | `rule.mitre.id[]`, `rule.mitre.tactic[]` | 36 % |
| src_ip | `data.srcip` (Wazuh decoders) or `data.src_ip` (Suricata eve) | 63 % |
| dst_ip / dst_port | `data.dest_ip`, `data.dest_port` (eve); `data.dstip` = `"ip:port"` (fast.log) | 22 % |
| host | `predecoder.hostname` (syslog host); otherwise `agent.ip` | 37 % / 100 % |
| user | `data.dstuser`, `data.srcuser`, or `user=<x>` inside `full_log` (Dovecot) | <1 % / Dovecot |
| Suricata signature | `data.alert.signature`, `data.alert.category`, `data.alert.severity` | 22 % |
| url | `data.url` (Apache access log), `data.http.url` (Suricata) | 19 % |

Other observations:
* `agent.name` is always `"wazuh-client"`, so it cannot identify hosts. We learn an *agent ip → hostname* map
  from alerts that do carry `predecoder.hostname` and apply it to the rest (e.g. `10.143.2.4 → intranet-server`).
* **Duplicates:** every Dovecot event appears 3× (`mail.log`, `mail.info`, `syslog`), and every Suricata event
  appears 2× (`eve.json` + `fast.log`, the latter with the useless description "IDS event."). We recover the real
  signature from the `fast.log` line (`[**] [1:2013504:6] SIGNATURE [**]`) and deduplicate on
  (second, description, src, dst, port, host, user, url).
* Rule descriptions in russellmitchell: 38 distinct, e.g. *Dovecot Authentication Success* (14,436),
  *IDS event.* (8,958), *Web server 400 error code* (7,105), *Suricata TLS invalid record/traffic* (4,402).

### Example (real alert, shortened)
```json
{"@timestamp": "2022-01-21T09:40:06.000000Z",
 "agent": {"ip": "172.19.130.4", "name": "wazuh-client"},
 "predecoder": {"hostname": "mail", "program_name": "sshd"},
 "rule": {"level": 3, "description": "sshd: authentication success.",
          "mitre": {"id": ["T1078", "T1021"], "tactic": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access", "Lateral Movement"]}},
 "data": {"srcip": "172.19.131.174", "dstuser": "jhall", "srcport": "36256"},
 "full_log": "Jan 21 09:40:06 mail sshd[10046]: Accepted publickey for jhall from 172.19.131.174 port 36256 ssh2: ..."}
```
becomes the sentence
`At 09:40:06, host mail reported 'sshd: authentication success' for user jhall from 172.19.131.174 (level 3).`

## Labels

`labels.csv` gives **time windows**, not per-alert labels. Phases per scenario: network_scans, service_scans,
dirb, wpscan, webshell, cracking, reverse_shell, privilege_escalation, service_stop, dnsteal.
An alert is assigned the phase whose window contains its timestamp, otherwise `normal`. This is approximate:
benign background alerts (e.g. Dovecot logins) inside a window also get that window's label.

Alerts in attack windows (raw counts, before deduplication):

| Phase | russellmitchell | shaw |
|---|---|---|
| network_scans | 8 | 3 |
| service_scans | 167 | 1 |
| dirb | 4,459 | 4,459 |
| wpscan | 3,172 | 729 |
| webshell | 4 | 0 |
| cracking | 10 | 647 |
| reverse_shell | 0 | 3 |
| privilege_escalation | 6 | 19 |
| dnsteal | 711 | 105 |

Attacker IP (from the dirb/wpscan windows): russellmitchell `172.19.131.174`, shaw `172.24.249.224`.

## Bundled sample

`data/sample/sample_alerts.json` is built by `backend/scripts/make_sample.py` from **russellmitchell**:
1,515 raw alerts from 2022-01-24 03:00–04:45 and 13:45–14:30 UTC (all attack phases). The flood of
*Web server 400 error code* alerts keeps every 6th alert and Dovecot/ClamAV background every 3rd; the rest is
kept as is. After deduplication the app sees 1,467 alerts.
