"""Build data/sample/sample_alerts.json from the real russellmitchell scenario of AIT-ADS.

The sample keeps the raw Wazuh JSON format (one alert per line), so the app parses it
exactly like an uploaded file.  It covers the attack day (2022-01-24):
  * 03:00-04:45  scans, dirb, wpscan, webshell, cracking, reverse shell, privilege escalation
  * 13:45-14:30  service stop + DNS exfiltration (dnsteal)
Sampling (documented so numbers can be explained):
  * the very frequent "Web server 400 error code" flood (dirb/wpscan) keeps every 6th alert
  * "Dovecot Authentication Success" / "ClamAV" background keeps every 3rd alert
  * everything else in the windows is kept.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "data" / "raw" / "ait_ads" / "russellmitchell_wazuh.json"
OUT = ROOT / "data" / "sample" / "sample_alerts.json"

WINDOWS = [("2022-01-24T03:00", "2022-01-24T04:45"), ("2022-01-24T13:45", "2022-01-24T14:30")]
EVERY = {"31101": 6, "31151": 6, "9701": 3, "52507": 3, "86601": 3, "20101": 3}


def main():
    counters = {}
    kept = []
    with open(SRC, encoding="utf-8") as f:
        for line in f:
            a = json.loads(line)
            ts = a["@timestamp"][:16]
            if not any(s <= ts < e for s, e in WINDOWS):
                continue
            rid = a["rule"]["id"]
            step = EVERY.get(rid, 1)
            counters[rid] = counters.get(rid, 0) + 1
            if (counters[rid] - 1) % step == 0:
                kept.append(line.strip())
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(kept) + "\n", encoding="utf-8")
    print(f"wrote {len(kept)} alerts to {OUT}")


if __name__ == "__main__":
    main()
