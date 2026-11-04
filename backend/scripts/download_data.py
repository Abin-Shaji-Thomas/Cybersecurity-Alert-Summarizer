"""Download the AIT Alert Data Set (AIT-ADS) from Zenodo into data/raw/.

AIT-ADS: Landauer et al., Zenodo record 8263181, licence CC BY 4.0.
Usage (from repo root):  backend\\.venv\\Scripts\\python backend\\scripts\\download_data.py
"""
import hashlib
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "data" / "raw"

ZIP_URL = "https://zenodo.org/records/8263181/files/ait_ads.zip?download=1"
ZIP_MD5 = "43db6b1f0996e0024befd617706c50e9"
LABELS_URL = "https://zenodo.org/records/8263181/files/labels.csv?download=1"


def md5_of(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url, dest):
    if dest.exists():
        print(f"already have {dest.name}")
        return
    print(f"downloading {url} ...")
    urllib.request.urlretrieve(url, dest)
    print(f"saved {dest} ({dest.stat().st_size / 1e6:.1f} MB)")


def main():
    RAW.mkdir(parents=True, exist_ok=True)
    zip_path = RAW / "ait_ads.zip"
    download(ZIP_URL, zip_path)
    digest = md5_of(zip_path)
    if digest != ZIP_MD5:
        raise SystemExit(f"MD5 mismatch: got {digest}, expected {ZIP_MD5}. Delete the file and retry.")
    print("MD5 OK")
    download(LABELS_URL, RAW / "labels.csv")

    out_dir = RAW / "ait_ads"
    if not out_dir.exists():
        out_dir.mkdir()
        with zipfile.ZipFile(zip_path) as z:
            for member in z.namelist():
                # guard against path traversal in the archive
                target = (out_dir / member).resolve()
                if not str(target).startswith(str(out_dir.resolve())):
                    raise SystemExit(f"unsafe path in zip: {member}")
            z.extractall(out_dir)
    print("extracted files:")
    for p in sorted(out_dir.rglob("*")):
        if p.is_file():
            print(f"  {p.relative_to(RAW)}  {p.stat().st_size / 1e6:.1f} MB")


if __name__ == "__main__":
    main()
