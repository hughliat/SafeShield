#!/bin/bash
# 安全盾 SafeShield 构建脚本(无 Xcode 环境:CommandLineTools swiftc 直编 + 手工组装 .app bundle)
set -euo pipefail
cd "$(dirname "$0")"

OUT="build"
APP="$OUT/SafeShield.app"
BIN="$APP/Contents/MacOS/SafeShield"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

echo ">> 编译 ($(ls Sources/*/*.swift | wc -l | tr -d ' ') 个 Swift 文件)"
swiftc -parse-as-library -O \
  -framework SwiftUI -framework AppKit -framework CryptoKit \
  $(find Sources -name '*.swift' | sort) \
  -o "$BIN"

echo ">> 组装 bundle"
cp Info.plist "$APP/Contents/Info.plist"
cp Resources/rules.default.json "$APP/Contents/Resources/rules.default.json"
cp Resources/SafeShield.icns "$APP/Contents/Resources/SafeShield.icns"
cat > "$APP/Contents/PkgInfo" <<'EOF'
APPL????
EOF

echo ">> 完成:$APP"
echo "   运行:open $APP  或  $BIN"
