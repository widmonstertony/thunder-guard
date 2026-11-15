"""Prepare offline country ranges and approximate map labels from pinned public data."""
import csv
import gzip
import hashlib
import ipaddress
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / "Build/Geography"
FILES = {
    "dbip-country-lite-2026-11.csv.gz": "e5c8459d638a272ece7f4d7cfa49dce18d91b4f403f6940ba9249bf0db3781fd",
    "ne_110m_admin_0_countries.geojson": "6866c877d39cba9c357620878839b336d569f8c662d3cfab4cb1dbe2d39c977f",
}


def main():
    for name, sha in FILES.items():
        if hashlib.sha256((WORK / name).read_bytes()).hexdigest() != sha:
            raise SystemExit(f"Geography source does not match pinned version: {name}")
    ranges = {4: [], 6: []}
    with gzip.open(WORK / next(iter(FILES)), "rt", newline="") as file:
        for first, last, cc in csv.reader(file):
            if len(cc) != 2 or not cc.isascii() or not cc.isalpha():
                continue
            lo, hi = ipaddress.ip_address(first), ipaddress.ip_address(last)
            if lo.version != hi.version or lo > hi:
                raise ValueError("Invalid address range")
            ranges[lo.version].append((lo.packed, hi.packed, cc.encode("ascii")))
    resources = WORK / "Resources"
    resources.mkdir(exist_ok=True)
    for ip, items in ranges.items():
        items.sort()
        if not items or any(a[1] >= b[0] for a, b in zip(items, items[1:])):
            raise ValueError(f"Unexpected overlap or empty IP{ip} table")
        (resources / f"ip{ip}ranges.bin").write_bytes(b"".join(a + b + cc for a, b, cc in items))
    label_positions = {}
    for row in json.loads((WORK / list(FILES)[1]).read_text())["features"]:
        p = row["properties"]
        cc = p.get("ISO_A2_EH", p.get("ISO_A2"))
        if not isinstance(cc, str) or len(cc) != 2 or not cc.isalpha():
            continue
        lon, lat = p["LABEL_X"], p["LABEL_Y"]
        if -180 <= lon <= 180 and -90 <= lat <= 90:
            label_positions[cc] = {"latitude": lat, "longitude": lon}
    (resources / "map-centers.json").write_text(json.dumps(label_positions, sort_keys=True, separators=(",", ":")))
    shutil.copy2(ROOT / "P2PGuard/Resources/Geography-NOTICE.txt", resources)
    print(f"{len(ranges[4])} IPv4 ranges, {len(ranges[6])} IPv6 ranges, {len(label_positions)} labels")


if __name__ == "__main__":
    main()
