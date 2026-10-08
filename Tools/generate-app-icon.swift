import AppKit
import Foundation

private let canvas: CGFloat = 1024

private func color(_ hex: UInt32, alpha: CGFloat = 1) -> NSColor {
    NSColor(
        calibratedRed: CGFloat((hex >> 16) & 0xFF) / 255,
        green: CGFloat((hex >> 8) & 0xFF) / 255,
        blue: CGFloat(hex & 0xFF) / 255,
        alpha: alpha
    )
}

private func drawText(
    _ value: String,
    center: CGPoint,
    font: NSFont,
    foreground: NSColor,
    tracking: CGFloat = 0
) {
    let attributes: [NSAttributedString.Key: Any] = [
        .font: font,
        .foregroundColor: foreground,
        .kern: tracking
    ]
    let text = value as NSString
    let size = text.size(withAttributes: attributes)
    text.draw(
        in: CGRect(
            x: center.x - size.width / 2,
            y: center.y - size.height / 2,
            width: size.width + 2,
            height: size.height + 2
        ),
        withAttributes: attributes
    )
}

private func drawArrow(from start: CGPoint, to tip: CGPoint, controls: (CGPoint, CGPoint), tint: NSColor) {
    let route = NSBezierPath()
    route.move(to: start)
    route.curve(to: tip, controlPoint1: controls.0, controlPoint2: controls.1)
    route.lineWidth = 24
    route.lineCapStyle = .round
    route.lineJoinStyle = .round
    tint.setStroke()
    route.stroke()

    let arrowHead = NSBezierPath()
    arrowHead.move(to: tip)
    arrowHead.line(to: CGPoint(x: tip.x - 44, y: tip.y + 26))
    arrowHead.line(to: CGPoint(x: tip.x - 44, y: tip.y - 26))
    arrowHead.close()
    tint.setFill()
    arrowHead.fill()
}

private func drawTunnelPortal() {
    let outer = NSBezierPath(roundedRect: CGRect(x: 785, y: 630, width: 190, height: 124), xRadius: 48, yRadius: 48)
    color(0x61B7FF, alpha: 0.13).setFill()
    outer.fill()
    color(0x61B7FF, alpha: 0.82).setStroke()
    outer.lineWidth = 8
    outer.stroke()

    let inner = NSBezierPath(roundedRect: CGRect(x: 816, y: 649, width: 128, height: 86), xRadius: 42, yRadius: 42)
    color(0x9AD4FF, alpha: 0.84).setStroke()
    inner.lineWidth = 5
    inner.stroke()
}

private func drawIcon(pixelSize: Int) -> Data {
    let bitmap = NSBitmapImageRep(
        bitmapDataPlanes: nil,
        pixelsWide: pixelSize,
        pixelsHigh: pixelSize,
        bitsPerSample: 8,
        samplesPerPixel: 4,
        hasAlpha: true,
        isPlanar: false,
        colorSpaceName: .deviceRGB,
        bytesPerRow: 0,
        bitsPerPixel: 0
    )!
    let context = NSGraphicsContext(bitmapImageRep: bitmap)!

    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = context
    context.imageInterpolation = .high
    context.shouldAntialias = true
    context.cgContext.scaleBy(x: CGFloat(pixelSize) / canvas, y: CGFloat(pixelSize) / canvas)

    let background = NSBezierPath(rect: CGRect(x: 0, y: 0, width: canvas, height: canvas))
    color(0x0B1729).setFill()
    background.fill()

    let tile = NSBezierPath(roundedRect: CGRect(x: 34, y: 34, width: 956, height: 956), xRadius: 218, yRadius: 218)
    color(0x112643).setFill()
    tile.fill()
    color(0xFFFFFF, alpha: 0.14).setStroke()
    tile.lineWidth = 7
    tile.stroke()

    let vpnAttributes: [NSAttributedString.Key: Any] = [
        .font: NSFont.systemFont(ofSize: 198, weight: .black),
        .foregroundColor: color(0xF7FAFF),
        .kern: -3
    ]
    let vpn = "VPN" as NSString
    let vpnSize = vpn.size(withAttributes: vpnAttributes)
    vpn.draw(
        in: CGRect(x: 90, y: 630, width: vpnSize.width + 12, height: vpnSize.height + 12),
        withAttributes: vpnAttributes
    )

    let splitPoint = CGPoint(x: 630, y: 535)
    let connector = NSBezierPath()
    connector.move(to: CGPoint(x: 525, y: 635))
    connector.curve(to: splitPoint, controlPoint1: CGPoint(x: 570, y: 630), controlPoint2: CGPoint(x: 565, y: 560))
    connector.lineWidth = 23
    connector.lineCapStyle = .round
    color(0xB8C7DD).setStroke()
    connector.stroke()

    drawTunnelPortal()

    drawArrow(
        from: splitPoint,
        to: CGPoint(x: 960, y: 692),
        controls: (CGPoint(x: 700, y: 555), CGPoint(x: 745, y: 692)),
        tint: color(0x61B7FF)
    )
    drawArrow(
        from: splitPoint,
        to: CGPoint(x: 960, y: 380),
        controls: (CGPoint(x: 700, y: 510), CGPoint(x: 745, y: 380)),
        tint: color(0x55E1A6)
    )

    let node = NSBezierPath(ovalIn: CGRect(x: splitPoint.x - 30, y: splitPoint.y - 30, width: 60, height: 60))
    color(0xF7FAFF).setFill()
    node.fill()
    color(0x88AADE).setStroke()
    node.lineWidth = 6
    node.stroke()

    drawText(
        "SPLIT TUNNEL",
        center: CGPoint(x: 512, y: 160),
        font: .systemFont(ofSize: 60, weight: .semibold),
        foreground: color(0xD7E2F2),
        tracking: 8
    )

    context.flushGraphics()
    NSGraphicsContext.restoreGraphicsState()
    return bitmap.representation(using: .png, properties: [:])!
}

let outputDirectory = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
try FileManager.default.createDirectory(at: outputDirectory, withIntermediateDirectories: true)

let iconSizes: [(name: String, pixels: Int)] = [
    ("AppIcon-16.png", 16),
    ("AppIcon-16@2x.png", 32),
    ("AppIcon-32.png", 32),
    ("AppIcon-32@2x.png", 64),
    ("AppIcon-128.png", 128),
    ("AppIcon-128@2x.png", 256),
    ("AppIcon-256.png", 256),
    ("AppIcon-256@2x.png", 512),
    ("AppIcon-512.png", 512),
    ("AppIcon-512@2x.png", 1024)
]

for icon in iconSizes {
    try drawIcon(pixelSize: icon.pixels).write(to: outputDirectory.appendingPathComponent(icon.name))
}
