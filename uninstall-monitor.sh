#!/bin/zsh
set -euo pipefail
agent="$HOME/Library/LaunchAgents/local.thunderguard.monitor.plist"
/bin/launchctl bootout "gui/$(id -u)/local.thunderguard.monitor" >/dev/null 2>&1 || true
if [[ -f "$agent" ]]; then
    backup="${agent}.disabled-$(/bin/date +%Y%m%d-%H%M%S)-$$"
    /bin/mv "$agent" "$backup"
    print "Retired legacy monitor: $backup"
fi
print 'Thunder Guard no longer restarts LuLu. Existing firewall rules are unchanged.'
