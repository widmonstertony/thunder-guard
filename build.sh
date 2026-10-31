#!/bin/zsh
set -euo pipefail
cd "${0:A:h}"
mkdir -p 'Build/Thunder Guard.app/Contents/MacOS' 'Build/Thunder Guard.app/Contents/Resources'
mkdir -p Build/ModuleCache
mkdir -p Build/ThunderGuard.iconset
for size in 16 32 128 256 512; do
    /usr/bin/sips -z "$size" "$size" Assets/ThunderGuard-1024.png --out "Build/ThunderGuard.iconset/icon_${size}x${size}.png" >/dev/null
    doubled=$((size * 2))
    /usr/bin/sips -z "$doubled" "$doubled" Assets/ThunderGuard-1024.png --out "Build/ThunderGuard.iconset/icon_${size}x${size}@2x.png" >/dev/null
done
/usr/bin/iconutil -c icns Build/ThunderGuard.iconset -o 'Build/Thunder Guard.app/Contents/Resources/ThunderGuard.icns'
swiftc -parse-as-library -swift-version 5 -O -module-cache-path Build/ModuleCache -framework SwiftUI -framework AppKit -framework Charts Sources/ThunderGuard.swift Sources/NetworkDashboard.swift Sources/CloudMagnetView.swift -o 'Build/Thunder Guard.app/Contents/MacOS/Thunder Guard'
cp Sources/guard.py 'Build/Thunder Guard.app/Contents/Resources/guard.py'
cp Sources/monitor.py 'Build/Thunder Guard.app/Contents/Resources/monitor.py'
cp Sources/network_snapshot.py 'Build/Thunder Guard.app/Contents/Resources/network_snapshot.py'
cat > 'Build/Thunder Guard.app/Contents/Info.plist' <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>local.thunderguard.app</string>
<key>CFBundleName</key><string>Thunder Guard</string>
<key>CFBundleDisplayName</key><string>迅雷护栏</string>
<key>CFBundleExecutable</key><string>Thunder Guard</string>
<key>CFBundleIconFile</key><string>ThunderGuard</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleVersion</key><string>6</string>
<key>CFBundleShortVersionString</key><string>0.3.3</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
</dict></plist>
PLIST
codesign --force --deep --sign - 'Build/Thunder Guard.app'
codesign --verify --deep --strict 'Build/Thunder Guard.app'
