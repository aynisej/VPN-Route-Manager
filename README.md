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

## Important limitation

App rules are implemented as IP routes in macOS's system routing table. They are learned from the selected process's open network connections, but the resulting route applies to every app connecting to the same IP address. This is best-effort IP-based routing, not true per-process isolation. Apps that delegate networking to helper processes may not expose all of their connections to the collector.

Domain rules resolve to the IP addresses returned when you apply them. Reapply a rule if a domain's addresses change. A VPN client may replace routes it does not manage.

## Privacy

Rules and collected IP addresses are stored locally in the app's preferences. Nothing in the app uploads them. JSON export is initiated manually and may contain domain names, IP addresses, or app names, so exported policy files are excluded by `.gitignore`.

## License

VPN Route Manager is licensed under GNU GPL version 3 only (`GPL-3.0-only`). See [LICENSE](LICENSE) for the full terms.

Copyright © 2026 aynisej.

## Requirements

- macOS 13 or later
- Xcode 16 or later

## Build in Xcode

1. Open `VPN Route Manager.xcodeproj`.
2. Select the `VPNRouteManager` scheme.
3. Build and run the app.

The Swift package can also be built from the project directory with `swift build`.
