#!/usr/bin/env python3
"""Read a bounded, one-shot macOS nettop sample for the visual dashboard."""

import csv
import io
import ipaddress
import json
import re
import subprocess
import sys

PROCESS = re.compile(r'^(.*)\.(\d+)$')
PORT = re.compile(r'[:.](\d+)$')


def number(value):
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def remote_parts(raw):
    match = PORT.search(raw)
    if not match:
        return raw, ''
    return raw[:match.start()], match.group(1)


def scope(address):
    if not address or address.startswith('*'):
        return 'unknown'
    try:
        ip = ipaddress.ip_address(address.split('%', 1)[0])
    except ValueError:
        return 'unknown'
    if ip.is_loopback:
        return 'loopback'
    if ip.is_global:
        return 'internet'
    return 'local'


def parse_nettop(data):
    reader = csv.reader(io.StringIO(data))
    apps = []
    current = None
    next(reader, None)
    for row in reader:
        if len(row) < 6:
            continue
        label = row[1].strip()
        if not label:
            continue
        if '<->' not in label:
            match = PROCESS.fullmatch(label)
            if match:
                current = {'pid': int(match.group(2)), 'name': match.group(1),
                           'received': number(row[4]),
                           'sent': number(row[5]),
                           'connections': []}
                apps.append(current)
            continue
        if current is None:
            continue
        protocol, _, addresses = label.partition(' ')
        if '<->' not in addresses:
            continue
        local, remote = addresses.split('<->', 1)
        address, port = remote_parts(remote)
        if not address or address.startswith('*'):
            continue
        current['connections'].append({
            'protocol': protocol, 'local': local, 'remote': address,
            'port': port, 'state': row[3],
            'interface': row[2], 'scope': scope(address),
            'received': number(row[4]),
            'sent': number(row[5]),
        })
    return {'apps': apps}


def main():
    try:
        result = subprocess.run(['/usr/bin/nettop', '-n', '-L', '1', '-x'],
                                capture_output=True, text=True, timeout=5,
                                check=True)
        print(json.dumps(parse_nettop(result.stdout), ensure_ascii=False))
    except (OSError, subprocess.SubprocessError) as exc:
        print(f'nettop sampling failed: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
