"""Cut small, ready-to-upload alert files from the real AIT-ADS 'shaw' scenario into test_samples/.

Each file keeps the raw Wazuh JSON-lines format, so it is parsed exactly like any uploaded file.
Usage (from repo root):  backend\\.venv\\Scripts\\python backend\\scripts\\make_test_samples.py
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "data" / "raw" / "ait_ads" / "shaw_wazuh.json"
OUT = ROOT / "test_samples"

FLOOD_RULES = {"31101", "31151"}          # "Web server 400 error code" floods (dirb / wpscan)
BACKGROUND_RULES = {"9701", "52507"}       # Dovecot login success / ClamAV update (normal background)

# name -> (list of (start, end) UTC windows, keep every Nth flood alert, keep every Nth background alert)
FILES = {
    "login_bruteforce.json": ([("2022-01-29T13:05", "2022-01-29T13:50")], 1, 2),
    "web_scan_dirb_wpscan.json": ([("2022-01-29T14:38:30", "2022-01-29T14:39:45")], 12, 1),
    "suspicious_dns_tls.json": ([("2022-01-29T12:00", "2022-01-29T12:15"), ("2022-01-29T14:44", "2022-01-29T15:06")], 1, 4),
    "mixed_attack_chain.json": ([("2022-01-29T14:37", "2022-01-29T15:22")], 20, 3),
}


def main():
    OUT.mkdir(exist_ok=True)
    lines = SRC.read_text(encoding="utf-8").splitlines()
    for name, (windows, flood_every, bg_every) in FILES.items():
        kept, counters = [], {"flood": 0, "bg": 0}
        for line in lines:
            a = json.loads(line)
            ts = a.get("@timestamp", "")[:19]
            if not any(s <= ts < e for s, e in windows):
                continue
            rule = str((a.get("rule") or {}).get("id"))
            kind = "flood" if rule in FLOOD_RULES else "bg" if rule in BACKGROUND_RULES else None
            if kind:
                counters[kind] += 1
                if (counters[kind] - 1) % (flood_every if kind == "flood" else bg_every):
                    continue
            kept.append(line)
        (OUT / name).write_text("\n".join(kept) + "\n", encoding="utf-8")
        print(f"{name}: {len(kept)} raw alerts")
    (OUT / "bad_file.txt").write_text("This is not an alert file.\nThe app should reject it with a clear error.\n",
                                      encoding="utf-8")


if __name__ == "__main__":
    main()
