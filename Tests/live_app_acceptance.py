"""Make and test a separate signed App with both ordinary HTTPS and BitTorrent.

Build the local probe with `prepare DIR`, then use P2P Guard's Add App picker
for the resulting bundle. Keep the global rule off for the per-app test so
the separate loopback peer is outside the target rule. The script does not
write preferences. Run both `verify DIR allow` and `verify DIR block` after
selecting the corresponding rule for the probe.
"""

import argparse
import datetime
import json
from pathlib import Path
import plistlib
import subprocess
import time

from live_p2p_acceptance import HERE, events_since, run_pair

APP_ID = "org.thunderguard.qa.peer-app"
EXECUTABLE = "TonTonPeerProbe"
APP_NAME = "TonTon Peer QA.app"


def paths(root):
    bundle = root / APP_NAME
    return bundle, bundle / "Contents/MacOS" / EXECUTABLE, root / "PeerFixtureControl"


def prepare(root):
    bundle, executable, control = paths(root)
    (bundle / "Contents/MacOS").mkdir(parents=True)
    plist = dict(CFBundlePackageType="APPL", CFBundleDisplayName="TonTon Peer QA",
                 CFBundleName="TonTon Peer QA", CFBundleIdentifier=APP_ID,
                 CFBundleExecutable=EXECUTABLE, CFBundleVersion="1", LSBackgroundOnly=True)
    (bundle / "Contents/Info.plist").write_bytes(plistlib.dumps(plist))
    fixture = HERE / "fixtures/metadata_peer.c"
    obj = root / "peer_fixture.o"
    subprocess.run(["clang", "-Wall", "-Wextra", "-Werror", fixture, "-o", control], check=True)
    subprocess.run(["clang", "-Wall", "-Wextra", "-Werror", "-Dmain=run_peer_fixture",
                    "-c", fixture, "-o", obj], check=True)
    subprocess.run(["clang", "-Wall", "-Wextra", "-Werror", "-fobjc-arc", "-framework",
                    "Foundation", HERE / "fixtures/app_probe.m", obj, "-o", executable], check=True)
    subprocess.run(["codesign", "--force", "--sign", "-", bundle], check=True)
    subprocess.run(["codesign", "--verify", "--strict", bundle], check=True)
    print(bundle)


def verify(root, rule, url):
    _, target, control = paths(root)
    start = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    https = subprocess.run([target, "--https", url], text=True, capture_output=True, timeout=20)
    results = [run_pair(control, target, connection, direction)
               for connection in ("outbound", "inbound") for direction in ("upload", "download")]
    by_process = []
    for attempt in range(4):
        by_process = events_since(start, EXECUTABLE)
        if rule == "block" and len(by_process) >= len(results):
            break
        if attempt != 3:
            time.sleep(0.5)
    for row in results:
        matched = [event for event in by_process if event.get("port") == row["remote_port"]]
        row["guard_verdicts"] = [
            {key: event.get(key) for key in ("app", "direction", "reason", "detail")} for event in matched
        ]
        if rule == "block":
            row["passed"] = row["metadata"] and not row["file_received"] and any(
                event.get("app") == APP_ID and event.get("direction") == row["direction"]
                and event.get("reason") == "bt-file" and event.get("detail") == "piece" for event in matched
            )
        else:
            row["passed"] = row["metadata"] and row["file_received"] and not matched
    result = {"app": APP_ID, "rule": rule, "https": https.stdout.strip() or https.stderr.strip(),
              "https_passed": https.returncode == 0, "peer_tests": results}
    print(json.dumps(result, indent=2))
    return 0 if result["https_passed"] and all(row["passed"] for row in results) else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("directory", type=Path)
    run = sub.add_parser("verify")
    run.add_argument("directory", type=Path)
    run.add_argument("rule", choices=["allow", "block"])
    run.add_argument("--url", default="https://example.com/")
    args = parser.parse_args()
    if args.action == "prepare":
        prepare(args.directory.resolve())
    else:
        raise SystemExit(verify(args.directory.resolve(), args.rule, args.url))
