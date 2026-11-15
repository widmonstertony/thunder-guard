"""Manual live acceptance. Requires a Mac with P2P Guard's IP rule enabled.

Only talks to 127.0.0.1 and never changes any filter settings. With
--baseline, prove that the fixture itself can transfer data before attempting
to verify a block. Otherwise require both a denied reception and our own
provider's directional verdict, after verifying real metadata receipt.
"""

import argparse
import datetime
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent
PREFIX = "P2PGUARD_BLOCK "


def run_pair(control, protected, establishment, direction):
    sending = direction == "upload"
    roles = {
        "client": (protected, "send" if sending else "recv"),
        "seed": (control, "recv" if sending else "send"),
    }
    connector = "seed" if establishment == "inbound" else "client"
    listener = "client" if connector == "seed" else "seed"
    exe, action = roles[listener]
    with subprocess.Popen([exe, "0", "listen", listener, action], text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as serve:
        try:
            ready = serve.stdout.readline().split()
            if len(ready) != 3 or ready[:2] != ["listener", "ready"]:
                raise RuntimeError(f"fixture could not listen: {ready}")
            port = ready[2]
            exe, action = roles[connector]
            connected = subprocess.run([exe, port, "connect", connector, action],
                                       capture_output=True, text=True, timeout=12)
            sout = serve.communicate(timeout=12)[0]
        finally:
            if serve.poll() is None:
                serve.kill()
                serve.wait()
    transcripts = {connector: connected.stdout, listener: sout}
    statuses = {connector: connected.returncode, listener: serve.returncode}
    receiver = "seed" if sending else "client"
    remote_port = next((line.removeprefix("remote port ") for line in transcripts["client"].splitlines()
                        if line.startswith("remote port ")), None)
    return {
        "direction": direction, "establishment": establishment, "remote_port": remote_port,
        "metadata": "metadata verified" in transcripts["client"]
                    and "metadata receiver confirmed" in transcripts["seed"],
        "file_received": "received file bytes" in transcripts[receiver],
        "peer_result": transcripts[receiver].strip().splitlines(),
        "statuses": statuses,
    }


def events_since(start, process):
    query = ('subsystem == "org.thunderguard.firewall" AND category == "packet-evidence" '
             'AND eventMessage BEGINSWITH "P2PGUARD_BLOCK "')
    out = subprocess.check_output(
        ["/usr/bin/log", "show", "--start", start, "--style", "compact", "--predicate", query], text=True
    )
    events = []
    for line in out.splitlines():
        if PREFIX not in line:
            continue
        try:
            event = json.loads(line.split(PREFIX, 1)[1])
        except ValueError:
            continue
        if event.get("process") == process and event.get("address") in ("127.0.0.1", "::ffff:127.0.0.1"):
            events.append(event)
    return events


def verify(baseline):
    start = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with tempfile.TemporaryDirectory(prefix="p2p-guard-acceptance-") as folder:
        root = Path(folder)
        control = root / "metadata-peer"
        # The development probe exercises the same executable-path attribution
        # that the real DownloadService uses. It never modifies Thunder.app.
        protected = root / "Thunder.app/Contents/MacOS" / f"GuardPeer-{root.name.rsplit('-', 1)[-1]}"
        protected.parent.mkdir(parents=True)
        subprocess.run(["clang", "-Wall", "-Wextra", "-Werror",
                        HERE / "fixtures/metadata_peer.c", "-o", control], check=True)
        shutil.copy2(control, protected)
        results = [run_pair(control, protected, "outbound", "upload"),
                   run_pair(control, protected, "outbound", "download"),
                   run_pair(control, protected, "inbound", "upload"),
                   run_pair(control, protected, "inbound", "download")]
        blocks = []
        if not baseline:
            for attempt in range(4):
                blocks = events_since(start, protected.name)
                if len(blocks) >= len(results):
                    break
                if attempt < 3:
                    time.sleep(0.5)
        for row in results:
            matching = next((ev for ev in blocks
                             if ev.get("direction") == row["direction"] and ev.get("reason") == "bt-file"
                             and ev.get("port") == row["remote_port"]), None)
            if matching:
                blocks.remove(matching)
            row["guard_verdict"] = bool(matching)
            row["passed"] = row["metadata"] and (
                row["file_received"] if baseline else not row["file_received"] and bool(matching)
            )
    print(json.dumps(results, indent=2))
    return 0 if all(row["passed"] for row in results) else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", action="store_true")
    args = parser.parse_args()
    raise SystemExit(verify(args.baseline))
