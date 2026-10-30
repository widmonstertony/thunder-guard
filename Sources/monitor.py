#!/usr/bin/env python3
"""Keep LuLu's user client running while Thunder Guard relies on its rules."""
import subprocess
import time

LULU = '/Applications/LuLu.app'


def running():
    return subprocess.run(['/usr/bin/pgrep', '-x', 'LuLu'],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          check=False).returncode == 0


def main():
    while True:
        if not running():
            subprocess.run(['/usr/bin/open', '-a', LULU],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=10, check=False)
        time.sleep(10)


if __name__ == '__main__':
    main()
