#!/bin/zsh
set -euo pipefail
# Retain the old entry point so old setup instructions cannot reinstall it.
print 'LuLu auto-restart has been removed. Retiring the legacy monitor instead.'
exec "${0:A:h}/uninstall-monitor.sh"
