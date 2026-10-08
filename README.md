# VPN Route Manager

VPN Route Manager is a native macOS app for creating and checking route rules while using an existing VPN client. It is built with SwiftUI and does not install or replace a VPN provider.

## Features

- Detects active macOS tunnel interfaces and selects the interface currently used by system routes.
- Routes domains, IP addresses, and CIDR networks through the selected VPN tunnel or directly through the active network gateway.
- Lets you choose a currently running app, observe its active public remote IP addresses, and apply routes for those IPs through the VPN or directly.
- Keeps website and app rules on separate screens in one app window.
- Checks the current system route for each saved rule and reports `WORK` or `NOT WORK` on the dashboard.
- Requests administrator authorization when adding or removing system routes.
- Stores rules locally and allows exporting them as JSON.
- Includes a custom macOS app icon showing VPN traffic splitting into tunnel and direct routes.

## Download a preview build

Choose the disk image that matches your Mac's processor:

- **Apple Silicon (M1, M2, M3, or M4):** [Download DMG](https://github.com/aynisej/VPN-Route-Manager/raw/refs/heads/main/VPN-Route-Manager-0.1.0-preview-Apple-Silicon.dmg)
- **Intel Mac:** [Download DMG](https://github.com/aynisej/VPN-Route-Manager/raw/refs/heads/main/VPN-Route-Manager-0.1.0-preview-Intel.dmg)

Open the downloaded DMG and drag **VPN Route Manager** to **Applications**. To check your processor, open **Apple menu → About This Mac**: it shows **Chip** on Apple Silicon Macs and **Processor** on Intel Macs.

These preview builds are ad-hoc signed and not notarized, so macOS may show a security prompt the first time they open. They are not ready for App Store submission.

## Important limitation

App rules are implemented as IP routes in macOS's system routing table. They are learned from the selected process's open network connections, but the resulting route applies to every app connecting to the same IP address. This is best-effort IP-based routing, not true per-process isolation. Apps that delegate networking to helper processes may not expose all of their connections to the collector.

Domain rules resolve to the IP addresses returned when you apply them. Reapply a rule if a domain's addresses change. A VPN client may replace routes it does not manage.

## Privacy

Rules and collected IP addresses are stored locally in the app's preferences. Nothing in the app uploads them. JSON export is initiated manually and may contain domain names, IP addresses, or app names, so exported policy files are excluded by `.gitignore`.

## License

The public source code is licensed under GNU GPL version 3 only (`GPL-3.0-only`). GPL permits commercial use and selling copies under its terms. See [LICENSE](LICENSE) for the full terms.

The copyright holder may also distribute official versions under a separate commercial license, including a paid Mac App Store release. This separate license applies only to those official commercial binaries; it does not remove GPL rights from the public source or copies distributed under the GPL. See [COMMERCIAL-DISTRIBUTION.md](COMMERCIAL-DISTRIBUTION.md).

Copyright © 2026 aynisej.

## Requirements

- macOS 13 or later
- Xcode 16 or later

## Build in Xcode

1. Open `VPN Route Manager.xcodeproj`.
2. Select the `VPNRouteManager` scheme.
3. Build and run the app.

The Swift package can also be built from the project directory with `swift build`.
