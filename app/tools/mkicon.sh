#!/bin/bash
# 图标生产管线:素材 PNG → Apple 超椭圆(squircle)遮罩 → 全尺寸 iconset → icns
# 用法:./tools/mkicon.sh <source-1024.png>
# 遮罩规格对齐 macOS 图标模板:1024 画布、824 形状、连续圆角(超椭圆 n=5)
set -euo pipefail
cd "$(dirname "$0")/.."
SRC="${1:?usage: mkicon.sh <source-1024.png>}"
WORK="build/iconwork"
ICONSET="$WORK/SafeShield.iconset"
rm -rf "$WORK"; mkdir -p "$ICONSET" "Resources"

echo ">> 遮罩:超椭圆 squircle (824/1024, n=5)"
cat > "$WORK/mask.swift" <<'SWIFT'
import AppKit
let args = CommandLine.arguments
guard let src = NSImage(contentsOfFile: args[1]) else { fatalError("cannot load \(args[1])") }
let S = 1024
let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: S, pixelsHigh: S, bitsPerSample: 8,
                           samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                           colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
let half = 824.0 / 2.0, c = 512.0, n = 5.0, steps = 1440
let path = NSBezierPath()
for i in 0...steps {
    let t = 2.0 * Double.pi * Double(i) / Double(steps)
    let ct = cos(t), st = sin(t)
    let x = c + half * (ct >= 0 ? 1 : -1) * pow(abs(ct), 2.0 / n)
    let y = c + half * (st >= 0 ? 1 : -1) * pow(abs(st), 2.0 / n)
    if i == 0 { path.move(to: NSPoint(x: x, y: y)) } else { path.line(to: NSPoint(x: x, y: y)) }
}
path.close()
path.addClip()
src.draw(in: NSRect(x: 0, y: 0, width: S, height: S))
NSGraphicsContext.restoreGraphicsState()
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: args[2]))
SWIFT
swift "$WORK/mask.swift" "$SRC" "$WORK/masked-1024.png"

echo ">> iconset 全尺寸"
emit() { sips -z "$1" "$1" "$WORK/masked-1024.png" --out "$ICONSET/$2" >/dev/null; }
emit 16   icon_16x16.png
emit 32   icon_16x16@2x.png
emit 32   icon_32x32.png
emit 64   icon_32x32@2x.png
emit 128  icon_128x128.png
emit 256  icon_128x128@2x.png
emit 256  icon_256x256.png
emit 512  icon_256x256@2x.png
emit 512  icon_512x512.png
emit 1024 icon_512x512@2x.png

echo ">> icns"
iconutil -c icns "$ICONSET" -o "Resources/SafeShield.icns"
cp "$WORK/masked-1024.png" "Resources/AppIcon-1024.png"
ls -lh Resources/SafeShield.icns
echo ">> 完成:Resources/SafeShield.icns"
