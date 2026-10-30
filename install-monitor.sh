#!/bin/zsh
set -euo pipefail
agent="$HOME/Library/LaunchAgents/local.thunderguard.monitor.plist"
mkdir -p "${agent:h}"
cat > "$agent" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>local.thunderguard.monitor</string>
<key>ProgramArguments</key><array>
<string>/usr/bin/python3</string>
<string>/Applications/Thunder Guard.app/Contents/Resources/monitor.py</string>
</array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
</dict></plist>
PLIST
launchctl bootout "gui/$(id -u)" "$agent" >/dev/null 2>&1 || true
launchctl bootstrap "gui/$(id -u)" "$agent"
launchctl enable "gui/$(id -u)/local.thunderguard.monitor"
