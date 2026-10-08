import AppKit
import Darwin
import SwiftUI
import UniformTypeIdentifiers

@main
struct VPNRouteManagerApp: App {
    var body: some Scene {
        Window("VPN Route Manager", id: "main") {
            AppRootView()
                .frame(minWidth: 700, minHeight: 560)
                .preferredColorScheme(.light)
        }
        .windowResizability(.contentSize)
    }
}

enum AppPage: Hashable {
    case dashboard
    case sites
    case apps
}

struct AppRootView: View {
    @State private var path: [AppPage] = []

    var body: some View {
        NavigationStack(path: $path) {
            DashboardView(navigate: navigate)
                .navigationTitle("VPN Route Manager")
                .navigationDestination(for: AppPage.self) { page in
                    switch page {
                    case .dashboard:
                        DashboardView(navigate: navigate)
                            .navigationTitle("VPN Route Manager")
                    case .sites:
                        SiteRulesView(navigate: navigate)
                            .navigationTitle("Правила сайтов")
                    case .apps:
                        AppRulesView(navigate: navigate)
                            .navigationTitle("Правила приложений")
                    }
                }
        }
    }

    private func navigate(_ page: AppPage) {
        if page == .dashboard { path.removeAll() }
        else { path = [page] }
    }
}

private enum RouteTarget: String, CaseIterable, Codable, Identifiable {
    case tunnel
    case direct

    var id: String { rawValue }
    var title: String { self == .tunnel ? "Через VPN" : "Напрямую" }
    var icon: String { self == .tunnel ? "lock.shield" : "arrow.up.right" }
}

private struct SiteRule: Codable, Identifiable, Equatable {
    var id = UUID().uuidString
    var destination: String
    var target: RouteTarget
}

private struct AppRule: Codable, Identifiable, Equatable {
    var id = UUID().uuidString
    var name: String
    var bundleID: String
    var path: String
    var target: RouteTarget
}

private struct AppliedRoute: Codable, Identifiable, Equatable {
    var id: String
    var ruleID: String
    var destination: String
    var isIPv6: Bool
    var interface: String
    var gateway: String?
}

private struct NetworkInterface: Identifiable, Hashable {
    let name: String
    var addresses: [String]

    var id: String { name }
    var isTunnel: Bool {
        ["utun", "tun", "tap", "ppp", "wg"].contains { name.hasPrefix($0) }
    }
    var label: String {
        let kind = isTunnel ? "VPN-туннель" : (name.hasPrefix("en") ? "Сеть" : "интерфейс")
        let address = addresses.first.map { " · \($0)" } ?? ""
        return "\(name) · \(kind)\(address)"
    }
}

private enum InterfaceScanner {
    static func scan() -> [NetworkInterface] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }

        var addresses: [String: Set<String>] = [:]
        var pointer: UnsafeMutablePointer<ifaddrs>? = first
        while let current = pointer {
            let item = current.pointee
            let name = String(cString: item.ifa_name)
            if let address = item.ifa_addr,
               item.ifa_flags & UInt32(IFF_UP) != 0,
               address.pointee.sa_family == UInt8(AF_INET) || address.pointee.sa_family == UInt8(AF_INET6) {
                var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                let result = host.withUnsafeMutableBufferPointer { buffer in
                    getnameinfo(
                        address,
                        socklen_t(address.pointee.sa_len),
                        buffer.baseAddress,
                        socklen_t(buffer.count),
                        nil,
                        0,
                        NI_NUMERICHOST
                    )
                }
                if result == 0 { addresses[name, default: []].insert(stringFromBuffer(host)) }
            }
            pointer = item.ifa_next
        }

        return addresses.map { NetworkInterface(name: $0.key, addresses: $0.value.sorted()) }
            .sorted { lhs, rhs in
                if lhs.isTunnel != rhs.isTunnel { return lhs.isTunnel }
                return lhs.name.localizedStandardCompare(rhs.name) == .orderedAscending
            }
    }
}

private struct NetworkGateway: Identifiable, Hashable {
    let address: String
    let interface: String
    let isIPv6: Bool

    var id: String { "\(interface)|\(address)" }
    var familyLabel: String { isIPv6 ? "IPv6" : "IPv4" }
}

private enum GatewayScanner {
    /// Reads macOS's active default routes and keeps only routes leaving through
    /// a currently up, non-tunnel interface. The first eligible system route wins.
    static func scan(interfaces: [NetworkInterface]) -> [NetworkGateway] {
        let availableInterfaces = Dictionary(uniqueKeysWithValues: interfaces.map { ($0.name, $0) })
        var gateways: [NetworkGateway] = []
        let netstat = URL(fileURLWithPath: "/usr/sbin/netstat")

        for (family, isIPv6) in [("inet", false), ("inet6", true)] {
            let process = Process()
            let output = Pipe()
            process.executableURL = netstat
            process.arguments = ["-rn", "-f", family]
            process.standardOutput = output
            process.standardError = FileHandle.nullDevice

            do {
                try process.run()
                let data = output.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                guard process.terminationStatus == 0,
                      let text = String(data: data, encoding: .utf8) else { continue }

                for line in text.split(whereSeparator: \.isNewline) {
                    let columns = line.split(whereSeparator: \.isWhitespace)
                    guard columns.count >= 4,
                          columns[0] == "default",
                          let interface = availableInterfaces[String(columns[3])],
                          !interface.isTunnel else { continue }

                    let address = String(columns[1])
                    let unscopedAddress = address.split(separator: "%", maxSplits: 1).first.map(String.init) ?? address
                    guard let parsed = ParsedDestination.parse(unscopedAddress),
                          parsed.isIPv6 == isIPv6,
                          parsed.prefix == (isIPv6 ? 128 : 32),
                          !gateways.contains(where: { $0.id == "\(interface.name)|\(address)" }) else { continue }

                    gateways.append(NetworkGateway(address: address, interface: interface.name, isIPv6: isIPv6))
                }
            } catch {
                continue
            }
        }
        return gateways
    }
}

private enum TunnelSelector {
    /// Follows the tunnel macOS is actually routing through, instead of picking
    /// the first utun name (which can belong to an inactive or unrelated service).
    static func preferredName(from tunnels: [NetworkInterface]) -> String? {
        let names = Set(tunnels.map(\.name))
        guard !names.isEmpty else { return nil }

        let probes: [[String]] = [
            ["-n", "get", "-inet", "default"],
            ["-n", "get", "-inet", "1.1.1.1"],
            ["-n", "get", "-inet6", "default"],
            ["-n", "get", "-inet6", "2606:4700:4700::1111"]
        ]
        for arguments in probes {
            if let name = routeInterface(arguments: arguments), names.contains(name) { return name }
        }

        let routeCounts = routeCountsByTunnel(names: names)
        if let best = routeCounts.max(by: { lhs, rhs in
            lhs.value == rhs.value ? lhs.key > rhs.key : lhs.value < rhs.value
        }), best.value > 0 {
            return best.key
        }
        return tunnels.first?.name
    }

    private static func routeInterface(arguments: [String]) -> String? {
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/sbin/route")
        process.arguments = arguments
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            let data = output.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            guard process.terminationStatus == 0,
                  let text = String(data: data, encoding: .utf8) else { return nil }
            for line in text.split(whereSeparator: \.isNewline) {
                let columns = line.split(separator: ":", maxSplits: 1).map(String.init)
                if columns.count == 2, columns[0].trimmingCharacters(in: .whitespaces) == "interface" {
                    return columns[1].trimmingCharacters(in: .whitespaces)
                }
            }
        } catch {
            return nil
        }
        return nil
    }

    private static func routeCountsByTunnel(names: Set<String>) -> [String: Int] {
        var counts: [String: Int] = [:]
        for family in ["inet", "inet6"] {
            let process = Process()
            let output = Pipe()
            process.executableURL = URL(fileURLWithPath: "/usr/sbin/netstat")
            process.arguments = ["-rn", "-f", family]
            process.standardOutput = output
            process.standardError = FileHandle.nullDevice
            do {
                try process.run()
                let data = output.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                guard process.terminationStatus == 0,
                      let text = String(data: data, encoding: .utf8) else { continue }
                for line in text.split(whereSeparator: \.isNewline) {
                    let columns = line.split(whereSeparator: \.isWhitespace)
                    guard columns.count >= 4 else { continue }
                    let interface = String(columns[3])
                    if names.contains(interface) { counts[interface, default: 0] += 1 }
                }
            } catch {
                continue
            }
        }
        return counts
    }
}

private struct ParsedDestination: Hashable {
    let address: String
    let prefix: Int
    let isIPv6: Bool

    var routeValue: String { "\(address)/\(prefix)" }

    static func parse(_ raw: String) -> ParsedDestination? {
        let pieces = raw.split(separator: "/", omittingEmptySubsequences: false)
        guard pieces.count == 1 || pieces.count == 2 else { return nil }
        let address = String(pieces[0]).trimmingCharacters(in: .whitespacesAndNewlines)
        guard !address.isEmpty else { return nil }

        let isIPv6: Bool
        var v4 = in_addr()
        var v6 = in6_addr()
        if address.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
            isIPv6 = false
        } else if address.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 {
            isIPv6 = true
        } else {
            return nil
        }

        let maximum = isIPv6 ? 128 : 32
        let prefix: Int
        if pieces.count == 2 {
            guard let supplied = Int(pieces[1]), (0...maximum).contains(supplied) else { return nil }
            prefix = supplied
        } else {
            prefix = maximum
        }
        return ParsedDestination(address: address, prefix: prefix, isIPv6: isIPv6)
    }
}

private enum DomainResolver {
    static func resolve(_ host: String) -> [ParsedDestination] {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        hints.ai_flags = AI_ADDRCONFIG

        var results: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &results) == 0, let first = results else { return [] }
        defer { freeaddrinfo(results) }

        var destinations = Set<ParsedDestination>()
        var current: UnsafeMutablePointer<addrinfo>? = first
        while let item = current {
            let info = item.pointee
            if let address = info.ai_addr {
                var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                let result = buffer.withUnsafeMutableBufferPointer { output in
                    getnameinfo(address, info.ai_addrlen, output.baseAddress, socklen_t(output.count), nil, 0, NI_NUMERICHOST)
                }
                if result == 0 {
                    let value = stringFromBuffer(buffer)
                    if let parsed = ParsedDestination.parse(value) { destinations.insert(parsed) }
                }
            }
            current = info.ai_next
        }
        return destinations.sorted { $0.routeValue < $1.routeValue }
    }
}

/// Learns public remote IPs from a selected app's live sockets. Host routes are
/// system-wide, so this is a best-effort app-to-IP mapping rather than true
/// per-process packet routing.
private enum ProcessConnectionScanner {
    static func scan(processIDs: [Int32]) -> [String] {
        var addresses = Set<String>()
        for processID in Set(processIDs) {
            let process = Process()
            let output = Pipe()
            process.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
            process.arguments = ["-nP", "-F", "n", "-a", "-p", String(processID), "-i"]
            process.standardOutput = output
            process.standardError = FileHandle.nullDevice
            do {
                try process.run()
                let data = output.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                guard let text = String(data: data, encoding: .utf8) else { continue }
                for line in text.split(whereSeparator: \.isNewline) where line.first == "n" {
                    guard let address = remoteAddress(in: String(line.dropFirst())), isPublicRoutable(address) else { continue }
                    addresses.insert(address)
                }
            } catch {
                continue
            }
        }
        return addresses.sorted()
    }

    private static func remoteAddress(in line: String) -> String? {
        guard let arrow = line.range(of: "->") else { return nil }
        let endpoint = line[arrow.upperBound...]
            .split(whereSeparator: \.isWhitespace)
            .first
            .map(String.init)?
            .trimmingCharacters(in: CharacterSet(charactersIn: "()"))
        guard let endpoint, !endpoint.isEmpty else { return nil }

        let host: String
        if endpoint.first == "[", let closingBracket = endpoint.firstIndex(of: "]") {
            host = String(endpoint[endpoint.index(after: endpoint.startIndex)..<closingBracket])
        } else if let colon = endpoint.lastIndex(of: ":") {
            host = String(endpoint[..<colon])
        } else {
            return nil
        }
        let unscopedHost = host.split(separator: "%", maxSplits: 1).first.map(String.init) ?? host
        return ParsedDestination.parse(unscopedHost)?.address
    }

    private static func isPublicRoutable(_ address: String) -> Bool {
        var ipv4 = in_addr()
        if address.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            let value = UInt32(bigEndian: ipv4.s_addr)
            let excluded: [(UInt32, Int)] = [
                (0x00000000, 8), (0x0A000000, 8), (0x64400000, 10),
                (0x7F000000, 8), (0xA9FE0000, 16), (0xAC100000, 12),
                (0xC0000000, 24), (0xC0000200, 24), (0xC0A80000, 16),
                (0xC6120000, 15), (0xC6336400, 24), (0xCB007100, 24),
                (0xE0000000, 4), (0xF0000000, 4)
            ]
            return !excluded.contains { network, prefix in
                let mask = prefix == 0 ? UInt32(0) : UInt32.max << (32 - prefix)
                return value & mask == network & mask
            }
        }

        let normalized = address.lowercased()
        return normalized != "::" && normalized != "::1"
            && !normalized.hasPrefix("fc") && !normalized.hasPrefix("fd")
            && !normalized.hasPrefix("fe80") && !normalized.hasPrefix("ff")
            && !normalized.hasPrefix("2001:db8:")
    }
}

private enum PolicyCodec {
    static func decode<T: Decodable>(_ value: String, as type: T.Type) -> T? {
        guard let data = value.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(type, from: data)
    }

    static func encode<T: Encodable>(_ value: T) -> String? {
        guard let data = try? JSONEncoder().encode(value) else { return nil }
        return String(data: data, encoding: .utf8)
    }
}

private struct RoutePolicyDocument: Codable {
    var format = "vpn-route-manager-policy-v1"
    var sites: [SiteRule]
    var applications: [AppRule]
}

private enum RuleHealthState {
    case checking
    case work
    case notWork

    var label: String {
        switch self {
        case .checking: "ПРОВЕРКА"
        case .work: "WORK"
        case .notWork: "NOT WORK"
        }
    }

    var color: Color {
        switch self {
        case .checking: .secondary
        case .work: .green
        case .notWork: .red
        }
    }
}

private struct RuleHealth: Identifiable {
    let id: String
    let title: String
    let icon: String
    let target: String
    let state: RuleHealthState
    let details: String
}

struct DashboardView: View {
    let navigate: (AppPage) -> Void
    @AppStorage("vpnroute.sites") private var storedSites = "[]"
    @AppStorage("vpnroute.apps") private var storedApps = "[]"
    @AppStorage("vpnroute.appObservedIPs") private var storedAppObservedIPs = "{}"
    @AppStorage("vpnroute.appAppliedRoutes") private var storedAppAppliedRoutes = "[]"
    @AppStorage("vpnroute.interface") private var selectedInterface = ""
    @AppStorage("vpnroute.interface.manual") private var manuallySelectedInterface = false
    @State private var interfaces: [NetworkInterface] = []
    @State private var gateways: [NetworkGateway] = []
    @State private var statusMessage: String?
    @State private var ruleHealth: [RuleHealth] = []
    @State private var isCheckingRules = false
    @State private var lastRulesCheck: Date?
    @State private var rulesCheckTask: Task<Void, Never>?

    private var sites: [SiteRule] { PolicyCodec.decode(storedSites, as: [SiteRule].self) ?? [] }
    private var apps: [AppRule] { PolicyCodec.decode(storedApps, as: [AppRule].self) ?? [] }
    private var tunnels: [NetworkInterface] { interfaces.filter(\.isTunnel) }
    private var interfaceSelection: Binding<String> {
        Binding(
            get: { selectedInterface },
            set: { selectedInterface = $0; manuallySelectedInterface = true }
        )
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                header
                intro
                connectionCard
                HStack(spacing: 14) {
                    ruleCard(title: "Правила сайтов", subtitle: "Домены, IP-адреса и сети CIDR", count: sites.count, icon: "globe", action: { navigate(.sites) })
                    ruleCard(title: "Правила приложений", subtitle: "Отдельный список установленных программ", count: apps.count, icon: "square.grid.2x2", action: { navigate(.apps) })
                }
                ruleHealthSection
                universalNote
                HStack {
                    Spacer()
                    Button(action: exportPolicy) { Label("Экспортировать политику", systemImage: "square.and.arrow.up") }
                        .buttonStyle(.bordered)
                }
            }
            .padding(28)
            .frame(maxWidth: 850, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .overlay(alignment: .bottom) {
            if let statusMessage {
                Text(statusMessage)
                    .font(.callout.weight(.medium))
                    .foregroundStyle(.white)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 10)
                    .background(.black.opacity(0.82), in: Capsule())
                    .padding(.bottom, 14)
            }
        }
        .onAppear(perform: refreshInterfaces)
        .onChange(of: storedSites) { _ in checkRules() }
        .onChange(of: storedApps) { _ in checkRules() }
        .onChange(of: storedAppObservedIPs) { _ in checkRules() }
        .onChange(of: storedAppAppliedRoutes) { _ in checkRules() }
        .onChange(of: selectedInterface) { _ in checkRules() }
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button { navigate(.sites) } label: { Label("Сайты", systemImage: "globe") }
                    .help("Открыть правила сайтов")
                Button { navigate(.apps) } label: { Label("Приложения", systemImage: "square.grid.2x2") }
                    .help("Открыть правила приложений")
            }
        }
    }

    private var header: some View {
        HStack(spacing: 11) {
            Image(systemName: "point.3.connected.trianglepath.dotted")
                .font(.system(size: 18, weight: .semibold))
                .foregroundStyle(.white)
                .frame(width: 38, height: 38)
                .background(.blue.gradient, in: RoundedRectangle(cornerRadius: 12))
            Text("VPN Route Manager").font(.headline.weight(.bold))
            Spacer()
            Label("Маршруты остаются на Mac", systemImage: "lock.fill")
                .font(.caption.weight(.medium))
                .foregroundStyle(.green)
                .padding(.horizontal, 11)
                .padding(.vertical, 7)
                .background(.green.opacity(0.08), in: Capsule())
        }
    }

    private var intro: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("УНИВЕРСАЛЬНОЕ УПРАВЛЕНИЕ МАРШРУТАМИ")
                .font(.caption2.weight(.bold)).tracking(1.3).foregroundStyle(.blue)
            Text("Выберите, что отправлять через VPN")
                .font(.system(size: 31, weight: .bold, design: .rounded)).tracking(-0.8)
            Text("Приложение работает с активными сетевыми туннелями macOS и не привязывает профиль к одному VPN-клиенту.")
                .font(.subheadline).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }

    private var connectionCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("Активный VPN-интерфейс", systemImage: "network")
                    .font(.headline)
                Spacer()
                Button(action: refreshInterfaces) { Label("Обновить", systemImage: "arrow.clockwise") }
                    .buttonStyle(.plain).font(.caption.weight(.medium))
            }
            if tunnels.isEmpty {
                Label("Туннель не найден. Подключите VPN и обновите список.", systemImage: "wifi.slash")
                    .font(.subheadline).foregroundStyle(.secondary)
            } else {
                Picker("Интерфейс", selection: interfaceSelection) {
                    ForEach(tunnels) { item in Text(item.label).tag(item.name) }
                }
                .labelsHidden()
                .pickerStyle(.menu)
                Text(manuallySelectedInterface
                     ? "Туннель выбран вручную. Нажмите «Обновить», чтобы снова выбрать основной активный VPN."
                     : "Автоматически выбран туннель, через который macOS сейчас направляет трафик.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(18)
        .background(.background, in: RoundedRectangle(cornerRadius: 16))
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(.quaternary, lineWidth: 1))
    }

    private func ruleCard(title: String, subtitle: String, count: Int, icon: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 13) {
                HStack {
                    Image(systemName: icon).font(.title3.weight(.semibold)).foregroundStyle(.blue)
                    Spacer()
                    Text("\(count)").font(.title3.weight(.bold)).foregroundStyle(.primary)
                }
                VStack(alignment: .leading, spacing: 4) {
                    Text(title).font(.headline).foregroundStyle(.primary)
                    Text(subtitle).font(.caption).foregroundStyle(.secondary)
                }
                Label("Открыть окно", systemImage: "arrow.up.right.square")
                    .font(.caption.weight(.medium)).foregroundStyle(.blue)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(17)
            .background(.background, in: RoundedRectangle(cornerRadius: 16))
            .overlay(RoundedRectangle(cornerRadius: 16).stroke(.quaternary, lineWidth: 1))
            .contentShape(RoundedRectangle(cornerRadius: 16))
        }
        .buttonStyle(.plain)
    }

    private var universalNote: some View {
        Label {
            Text("Для приложения собираются IP его активных соединений, затем macOS получает маршруты для этих IP. Такой маршрут общий для системы: другие приложения с тем же IP пойдут тем же путём.")
                .fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: "info.circle.fill").foregroundStyle(.blue)
        }
        .font(.caption).foregroundStyle(.secondary)
        .padding(15)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.blue.opacity(0.05), in: RoundedRectangle(cornerRadius: 14))
    }

    private var ruleHealthSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("Проверка правил", systemImage: "checkmark.shield")
                    .font(.headline)
                Spacer()
                Button(action: checkRules) {
                    if isCheckingRules { ProgressView().controlSize(.small) }
                    else { Label("Проверить", systemImage: "arrow.clockwise") }
                }
                .buttonStyle(.bordered)
                .disabled(isCheckingRules || (sites.isEmpty && apps.isEmpty))
            }

            if ruleHealth.isEmpty {
                Text("Добавленные правила появятся здесь.")
                    .font(.subheadline).foregroundStyle(.secondary)
            } else {
                VStack(spacing: 0) {
                    ForEach(ruleHealth) { result in
                        HStack(spacing: 10) {
                            Image(systemName: result.icon).foregroundStyle(.blue).frame(width: 20)
                            VStack(alignment: .leading, spacing: 3) {
                                HStack(spacing: 6) {
                                    Text(result.title).font(.subheadline.weight(.semibold)).lineLimit(1)
                                    Text(result.target).font(.caption).foregroundStyle(.secondary)
                                }
                                Text(result.details).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                            }
                            Spacer(minLength: 8)
                            Text(result.state.label)
                                .font(.caption2.weight(.bold))
                                .foregroundStyle(result.state.color)
                                .padding(.horizontal, 9).padding(.vertical, 5)
                                .background(result.state.color.opacity(0.10), in: Capsule())
                        }
                        .padding(.vertical, 8)
                        if result.id != ruleHealth.last?.id { Divider() }
                    }
                }
            }

            if let lastRulesCheck {
                Text("Последняя проверка: \(lastRulesCheck.formatted(date: .omitted, time: .shortened))")
                    .font(.caption2).foregroundStyle(.tertiary)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background, in: RoundedRectangle(cornerRadius: 16))
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(.quaternary, lineWidth: 1))
    }

    private func refreshInterfaces() {
        let discovered = InterfaceScanner.scan()
        let discoveredTunnels = discovered.filter(\.isTunnel)
        interfaces = discovered
        if !discoveredTunnels.contains(where: { $0.name == selectedInterface }) {
            manuallySelectedInterface = false
        }
        if !manuallySelectedInterface {
            selectedInterface = TunnelSelector.preferredName(from: discoveredTunnels) ?? ""
        }
        gateways = GatewayScanner.scan(interfaces: discovered)
        checkRules()
    }

    private func checkRules() {
        rulesCheckTask?.cancel()
        let siteRules = sites
        let appRules = apps
        let observedIPs = PolicyCodec.decode(storedAppObservedIPs, as: [String: [String]].self) ?? [:]
        guard !siteRules.isEmpty || !appRules.isEmpty else {
            ruleHealth = []
            isCheckingRules = false
            lastRulesCheck = Date()
            return
        }

        isCheckingRules = true
        ruleHealth = siteRules.map { rule in
            RuleHealth(id: "site|\(rule.id)", title: rule.destination, icon: "globe", target: rule.target.title, state: .checking, details: "Проверяем системный маршрут…")
        } + appRules.map { rule in
            RuleHealth(id: "app|\(rule.id)", title: rule.name, icon: "app", target: rule.target.title, state: .checking, details: "Проверяем применение правила…")
        }

        let selectedTunnel = selectedInterface
        let availableGateways = gateways
        rulesCheckTask = Task { @MainActor in
            var results: [RuleHealth] = []
            for rule in siteRules {
                if Task.isCancelled { return }
                let destinations: [ParsedDestination]
                if let address = ParsedDestination.parse(rule.destination) {
                    destinations = [address]
                } else {
                    destinations = await Task.detached(priority: .userInitiated) {
                        DomainResolver.resolve(rule.destination)
                    }.value
                }
                let expectedGateway: NetworkGateway?
                if rule.target == .direct, let isIPv6 = destinations.first?.isIPv6 {
                    expectedGateway = availableGateways.first(where: { $0.isIPv6 == isIPv6 })
                } else {
                    expectedGateway = nil
                }
                let checks = await Task.detached(priority: .userInitiated) {
                    destinations.map { destination in
                        RouteStateReader.currentRouteMatches(
                            destination,
                            target: rule.target,
                            tunnelName: selectedTunnel,
                            directGateway: rule.target == .direct
                                ? availableGateways.first(where: { $0.isIPv6 == destination.isIPv6 })
                                : nil
                        )
                    }
                }.value
                let workingCount = checks.filter { $0 }.count
                let works = !destinations.isEmpty && workingCount == destinations.count
                let details: String
                if destinations.isEmpty {
                    details = "Не удалось разрешить домен или распознать адрес."
                } else if works {
                    details = rule.target == .tunnel
                        ? "Все \(destinations.count) адреса идут через \(selectedTunnel)."
                        : "Все \(destinations.count) адреса идут напрямую через \(expectedGateway?.interface ?? "сеть")."
                } else {
                    details = "Маршрут совпал для \(workingCount) из \(destinations.count) адресов."
                }
                results.append(RuleHealth(
                    id: "site|\(rule.id)",
                    title: rule.destination,
                    icon: "globe",
                    target: rule.target.title,
                    state: works ? .work : .notWork,
                    details: details
                ))
            }

            for rule in appRules {
                if Task.isCancelled { return }
                let destinations = (observedIPs[rule.bundleID] ?? []).compactMap(ParsedDestination.parse)
                guard !destinations.isEmpty else {
                    results.append(RuleHealth(
                        id: "app|\(rule.id)",
                        title: rule.name,
                        icon: "app",
                        target: rule.target.title,
                        state: .notWork,
                        details: "Пока нет собранных IP. Откройте окно приложений и запустите сбор трафика."
                    ))
                    continue
                }
                let checks = await Task.detached(priority: .userInitiated) {
                    destinations.map { destination in
                        RouteStateReader.currentRouteMatches(
                            destination,
                            target: rule.target,
                            tunnelName: selectedTunnel,
                            directGateway: rule.target == .direct
                                ? availableGateways.first(where: { $0.isIPv6 == destination.isIPv6 })
                                : nil
                        )
                    }
                }.value
                let workingCount = checks.filter { $0 }.count
                let works = workingCount == destinations.count
                let details = works
                    ? "Все \(destinations.count) IP идут \(rule.target == .tunnel ? "через \(selectedTunnel)" : "напрямую через сеть")."
                    : "По маршруту идут \(workingCount) из \(destinations.count) IP. Нажмите «Применить IP» в окне приложений."
                results.append(RuleHealth(
                    id: "app|\(rule.id)",
                    title: rule.name,
                    icon: "app",
                    target: rule.target.title,
                    state: works ? .work : .notWork,
                    details: details
                ))
            }
            guard !Task.isCancelled else { return }
            ruleHealth = results
            isCheckingRules = false
            lastRulesCheck = Date()
        }
    }

    private func exportPolicy() {
        let document = RoutePolicyDocument(sites: sites, applications: apps)
        guard let data = try? JSONEncoder().encode(document) else { return }
        let panel = NSSavePanel()
        panel.title = "Экспорт политики VPN Route Manager"
        panel.nameFieldStringValue = "vpn-route-policy.json"
        panel.allowedContentTypes = [.json]
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try data.write(to: url, options: .atomic)
            statusMessage = "Политика экспортирована."
        } catch {
            statusMessage = "Не удалось сохранить политику."
        }
    }
}

struct SiteRulesView: View {
    let navigate: (AppPage) -> Void
    @AppStorage("vpnroute.sites") private var storedRules = "[]"
    @AppStorage("vpnroute.interface") private var selectedInterface = ""
    @AppStorage("vpnroute.interface.manual") private var manuallySelectedInterface = false
    @AppStorage("vpnroute.applied") private var storedAppliedRoutes = "[]"
    @State private var rules: [SiteRule] = []
    @State private var appliedRoutes: [AppliedRoute] = []
    @State private var interfaces: [NetworkInterface] = []
    @State private var gateways: [NetworkGateway] = []
    @State private var newDestination = ""
    @State private var newTarget: RouteTarget = .tunnel
    @State private var statusMessage: String?
    @State private var isApplying = false

    private var tunnels: [NetworkInterface] { interfaces.filter(\.isTunnel) }
    private var interfaceSelection: Binding<String> {
        Binding(
            get: { selectedInterface },
            set: { selectedInterface = $0; manuallySelectedInterface = true }
        )
    }
    private var invalidRules: [String] { rules.map(\.destination).filter { !isSupportedDestination($0) } }
    private var hasDirectRules: Bool { rules.contains { $0.target == .direct } }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 19) {
                titleBlock
                tunnelCard
                addCard
                rulesCard
                if hasDirectRules { gatewayCard }
                actionRow
                if !appliedRoutes.isEmpty { appliedCard }
                siteInfo
            }
            .padding(24)
            .frame(maxWidth: 820, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .overlay(alignment: .bottom) {
            if let statusMessage {
                Text(statusMessage).font(.callout.weight(.medium)).foregroundStyle(.white)
                    .padding(.horizontal, 16).padding(.vertical, 10)
                    .background(.black.opacity(0.82), in: Capsule()).padding(.bottom, 14)
            }
        }
        .onAppear {
            rules = PolicyCodec.decode(storedRules, as: [SiteRule].self) ?? []
            appliedRoutes = PolicyCodec.decode(storedAppliedRoutes, as: [AppliedRoute].self) ?? []
            refreshInterfaces()
        }
        .onChange(of: rules) { _ in persistRules() }
        .onChange(of: appliedRoutes) { _ in storedAppliedRoutes = PolicyCodec.encode(appliedRoutes) ?? "[]" }
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button { navigate(.dashboard) } label: { Label("Главная", systemImage: "house") }
                Button { navigate(.apps) } label: { Label("Правила приложений", systemImage: "square.grid.2x2") }
            }
        }
    }

    private var titleBlock: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("СЕТЕВЫЕ ПРАВИЛА").font(.caption2.weight(.bold)).tracking(1.2).foregroundStyle(.blue)
            Text("Сайты и сети").font(.system(size: 28, weight: .bold, design: .rounded))
            Text("Домены преобразуются в текущие IP-адреса; IP и CIDR маршрутизируются напрямую через системную таблицу macOS.")
                .font(.subheadline).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }

    private var tunnelCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("VPN-интерфейс", systemImage: "network").font(.headline)
            if tunnels.isEmpty {
                Label("Активный туннель не найден", systemImage: "wifi.slash").font(.subheadline).foregroundStyle(.secondary)
            } else {
                Picker("Через какой туннель", selection: interfaceSelection) {
                    ForEach(tunnels) { item in Text(item.label).tag(item.name) }
                }
                .labelsHidden().pickerStyle(.menu)
                Text(manuallySelectedInterface
                     ? "Выбран вручную. Обновите список, чтобы автоматически выбрать основной активный VPN."
                     : "Основной активный VPN выбран автоматически по маршрутам macOS.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(16).background(.background, in: RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(.quaternary, lineWidth: 1))
    }

    private var addCard: some View {
        VStack(alignment: .leading, spacing: 11) {
            Text("Добавить правило").font(.headline)
            HStack(spacing: 9) {
                TextField("example.com, 203.0.113.4 или 203.0.113.0/24", text: $newDestination)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit(addRule)
                Picker("Маршрут", selection: $newTarget) {
                    ForEach(RouteTarget.allCases) { target in Text(target.title).tag(target) }
                }
                .frame(width: 145)
                Button(action: addRule) { Label("Добавить", systemImage: "plus") }
                    .buttonStyle(.borderedProminent)
                    .disabled(newDestination.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(16).background(.background, in: RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(.quaternary, lineWidth: 1))
    }

    private var rulesCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Правила").font(.headline)
                Spacer()
                Text("\(rules.count)").font(.caption.weight(.medium)).foregroundStyle(.secondary)
            }
            if rules.isEmpty {
                Text("Добавьте сайт, IP-адрес или сеть CIDR.").font(.subheadline).foregroundStyle(.secondary).padding(.vertical, 12)
            } else {
                ForEach($rules) { $rule in
                    HStack(spacing: 10) {
                        Image(systemName: ParsedDestination.parse(rule.destination) == nil ? "globe" : "network")
                            .foregroundStyle(.blue).frame(width: 20)
                        Text(rule.destination).font(.system(.body, design: .monospaced)).lineLimit(1)
                        Spacer(minLength: 8)
                        Picker("Направление", selection: $rule.target) {
                            ForEach(RouteTarget.allCases) { target in Text(target.title).tag(target) }
                        }
                        .labelsHidden().frame(width: 135)
                        Button(role: .destructive) { rules.removeAll { $0.id == rule.id } } label: {
                            Image(systemName: "trash").foregroundStyle(.secondary)
                        }
                        .buttonStyle(.plain).help("Удалить правило")
                    }
                    .padding(.vertical, 5)
                    if rule.id != rules.last?.id { Divider() }
                }
            }
            if !invalidRules.isEmpty {
                Label("Часть правил имеет неподдерживаемый формат.", systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(.orange)
            }
        }
        .padding(16).background(.background, in: RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(.quaternary, lineWidth: 1))
    }

    private var gatewayCard: some View {
        VStack(alignment: .leading, spacing: 9) {
            Label("Шлюз выбирается автоматически", systemImage: "sparkles").font(.headline)
            Text("Используется активный шлюз Wi‑Fi или Ethernet, найденный в таблице маршрутов macOS.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            ForEach([false, true], id: \.self) { isIPv6 in
                if let gateway = gateways.first(where: { $0.isIPv6 == isIPv6 }) {
                    Label("\(gateway.isIPv6 ? "IPv6" : "IPv4"): \(gateway.address) · \(gateway.interface)", systemImage: "checkmark.circle.fill")
                        .font(.caption.monospaced()).foregroundStyle(.green)
                } else {
                    Label("\(isIPv6 ? "IPv6" : "IPv4"): активный шлюз не найден", systemImage: "minus.circle")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .padding(16).background(.background, in: RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(.quaternary, lineWidth: 1))
    }

    private var actionRow: some View {
        HStack(spacing: 10) {
            Button(action: applyRules) {
                if isApplying { ProgressView().controlSize(.small) }
                else { Label("Применить маршруты", systemImage: "checkmark.shield") }
            }
            .buttonStyle(.borderedProminent)
            .disabled(isApplying || rules.isEmpty || !invalidRules.isEmpty || tunnels.isEmpty || (hasDirectRules && gateways.isEmpty))

            Button(action: removeAppliedRoutes) { Label("Убрать маршруты", systemImage: "arrow.uturn.backward") }
                .buttonStyle(.bordered).disabled(isApplying || appliedRoutes.isEmpty)

            Spacer()
            Button(action: refreshInterfaces) { Label("Обновить туннели", systemImage: "arrow.clockwise") }
                .buttonStyle(.plain).font(.caption.weight(.medium))
        }
    }

    private var appliedCard: some View {
        VStack(alignment: .leading, spacing: 9) {
            Text("Добавленные этим приложением маршруты").font(.headline)
            ForEach(appliedRoutes) { route in
                HStack {
                    Text(route.destination).font(.system(.caption, design: .monospaced))
                    Spacer()
                    Text(route.interface).font(.caption).foregroundStyle(.secondary)
                }
                Divider()
            }
        }
        .padding(16).background(.background, in: RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(.quaternary, lineWidth: 1))
    }

    private var siteInfo: some View {
        Label {
            Text("Для изменения таблицы маршрутов macOS покажет системный запрос администратора. Домены разрешаются через текущий DNS и превращаются в статические IP-маршруты; при смене IP правило нужно применить снова. Клиент VPN может переустанавливать собственные маршруты.")
                .fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: "info.circle.fill").foregroundStyle(.blue)
        }
        .font(.caption).foregroundStyle(.secondary)
    }

    private func refreshInterfaces() {
        let discovered = InterfaceScanner.scan()
        let discoveredTunnels = discovered.filter(\.isTunnel)
        interfaces = discovered
        if !discoveredTunnels.contains(where: { $0.name == selectedInterface }) {
            manuallySelectedInterface = false
        }
        if !manuallySelectedInterface {
            selectedInterface = TunnelSelector.preferredName(from: discoveredTunnels) ?? ""
        }
        gateways = GatewayScanner.scan(interfaces: interfaces)
    }

    private func addRule() {
        let value = newDestination.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty, !rules.contains(where: { $0.destination.caseInsensitiveCompare(value) == .orderedSame }) else { return }
        rules.append(SiteRule(destination: value, target: newTarget))
        newDestination = ""
    }

    private func persistRules() { storedRules = PolicyCodec.encode(rules) ?? "[]" }

    private func applyRules() {
        guard let tunnel = tunnels.first(where: { $0.name == selectedInterface }) else {
            statusMessage = "Сначала выберите активный VPN-интерфейс."
            return
        }
        isApplying = true
        Task { @MainActor in
            var pending: [AppliedRoute] = []
            var alreadyRouted = 0
            var unresolvedRules = 0
            var missingGatewayRoutes = 0
            for rule in rules {
                let destinations: [ParsedDestination]
                if let address = ParsedDestination.parse(rule.destination) {
                    destinations = [address]
                } else {
                    destinations = await Task.detached(priority: .userInitiated) {
                        DomainResolver.resolve(rule.destination)
                    }.value
                }
                if destinations.isEmpty { unresolvedRules += 1 }

                for destination in destinations {
                    let directGateway = rule.target == .direct ? gateways.first(where: { $0.isIPv6 == destination.isIPv6 }) : nil
                    if rule.target == .direct && directGateway == nil {
                        missingGatewayRoutes += 1
                        continue
                    }
                    let routeInterface = rule.target == .tunnel ? tunnel.name : (directGateway?.interface ?? "")
                    let routeGateway = directGateway?.address
                    guard routeTargetIsValid(destination, rule: rule, gateway: directGateway) else { continue }
                    let identifier = "\(rule.id)|\(destination.routeValue)|\(routeInterface)|\(routeGateway ?? "")"
                    let route = AppliedRoute(id: identifier, ruleID: rule.id, destination: destination.routeValue, isIPv6: destination.isIPv6, interface: routeInterface, gateway: routeGateway)
                    if RouteStateReader.alreadyMatches(
                        destination,
                        target: rule.target,
                        tunnelName: tunnel.name,
                        directGateway: directGateway
                    ) {
                        alreadyRouted += 1
                    } else if !pending.contains(where: { $0.id == identifier }) {
                        pending.append(route)
                    }
                }
            }
            guard !pending.isEmpty else {
                isApplying = false
                var summary: [String] = []
                if alreadyRouted > 0 { summary.append("Уже активно: \(alreadyRouted) маршрутов.") }
                if missingGatewayRoutes > 0 { summary.append("Для части адресов нет подходящего шлюза.") }
                if unresolvedRules > 0 { summary.append("Не удалось разрешить домены.") }
                statusMessage = summary.isEmpty ? "Новых маршрутов нет." : summary.joined(separator: " ")
                return
            }

            do {
                let results = try ElevatedRouteRunner.run(pending.map { $0.command(action: "add") })
                let successful = pending.filter { results.contains($0.id) }
                appliedRoutes.append(contentsOf: successful.filter { route in
                    !appliedRoutes.contains(where: { $0.id == route.id })
                })
                let failedCount = pending.count - successful.count
                var summary = failedCount == 0 ? "Добавлено маршрутов: \(successful.count)." : "Добавлено: \(successful.count), не удалось: \(failedCount). Проверьте подключение VPN."
                if alreadyRouted > 0 { summary += " Уже активно: \(alreadyRouted)." }
                if missingGatewayRoutes > 0 { summary += " Без подходящего шлюза: \(missingGatewayRoutes)." }
                if unresolvedRules > 0 { summary += " Не разрешено доменов: \(unresolvedRules)." }
                statusMessage = summary
            } catch {
                statusMessage = "Не удалось применить маршруты. Разрешите системный запрос администратора и повторите."
            }
            isApplying = false
        }
    }

    private func removeAppliedRoutes() {
        isApplying = true
        Task { @MainActor in
            do {
                let results = try ElevatedRouteRunner.run(appliedRoutes.map { $0.command(action: "delete") })
                appliedRoutes.removeAll { results.contains($0.id) }
                statusMessage = appliedRoutes.isEmpty ? "Маршруты удалены." : "Удалены доступные маршруты; некоторые уже изменены системой или VPN-клиентом."
            } catch {
                statusMessage = "Не удалось удалить маршруты."
            }
            isApplying = false
        }
    }
}

private struct RunningApplicationChoice: Identifiable {
    let name: String
    let bundleID: String
    let path: String

    var id: String { bundleID }
}

struct AppRulesView: View {
    let navigate: (AppPage) -> Void
    @AppStorage("vpnroute.apps") private var storedRules = "[]"
    @AppStorage("vpnroute.appObservedIPs") private var storedObservedIPs = "{}"
    @AppStorage("vpnroute.appAppliedRoutes") private var storedAppliedRoutes = "[]"
    @AppStorage("vpnroute.interface") private var selectedInterface = ""
    @AppStorage("vpnroute.interface.manual") private var manuallySelectedInterface = false
    @State private var rules: [AppRule] = []
    @State private var observedIPs: [String: [String]] = [:]
    @State private var appliedRoutes: [AppliedRoute] = []
    @State private var activeApplications: [RunningApplicationChoice] = []
    @State private var isShowingAppPicker = false
    @State private var appSearchText = ""
    @State private var collectingRuleID: String?
    @State private var collectionTask: Task<Void, Never>?
    @State private var isApplyingRuleID: String?
    @State private var isRemovingRoutes = false
    @State private var interfaces: [NetworkInterface] = []
    @State private var gateways: [NetworkGateway] = []
    @State private var statusMessage: String?

    private var tunnels: [NetworkInterface] { interfaces.filter(\.isTunnel) }
    private var activeTunnel: NetworkInterface? {
        tunnels.first(where: { $0.name == selectedInterface })
            ?? TunnelSelector.preferredName(from: tunnels).flatMap { name in tunnels.first(where: { $0.name == name }) }
    }
    private var filteredApplications: [RunningApplicationChoice] {
        let query = appSearchText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return activeApplications }
        return activeApplications.filter {
            $0.name.localizedCaseInsensitiveContains(query) || $0.bundleID.localizedCaseInsensitiveContains(query)
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("ПРАВИЛА ПРИЛОЖЕНИЙ").font(.caption2.weight(.bold)).tracking(1.2).foregroundStyle(.blue)
                    Text("Маршрутизация программ").font(.system(size: 28, weight: .bold, design: .rounded))
                    Text("Чтобы создать правило, выберите приложение из списка активных приложений.")
                        .font(.subheadline).foregroundStyle(.secondary)
                }
                HStack {
                    Button {
                        refreshActiveApplications()
                        isShowingAppPicker = true
                    } label: { Label("Выбрать активное приложение…", systemImage: "plus.app") }
                        .buttonStyle(.borderedProminent)
                    Spacer()
                    Text("\(rules.count) правил").font(.caption).foregroundStyle(.secondary)
                }
                if rules.isEmpty {
                    VStack(spacing: 9) {
                        Image(systemName: "square.grid.2x2").font(.system(size: 30)).foregroundStyle(.secondary)
                        Text("Приложений пока нет").font(.headline)
                        Text("Запустите нужную программу и выберите её в списке активных приложений.").font(.caption).foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, minHeight: 180)
                } else {
                    VStack(spacing: 12) {
                        ForEach($rules) { $rule in
                            VStack(alignment: .leading, spacing: 11) {
                                HStack(spacing: 12) {
                                    Image(nsImage: NSWorkspace.shared.icon(forFile: rule.path))
                                        .resizable().frame(width: 34, height: 34)
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text(rule.name).font(.subheadline.weight(.semibold))
                                        Text(rule.bundleID).font(.caption.monospaced()).foregroundStyle(.secondary)
                                    }
                                    Spacer()
                                    Picker("Маршрут", selection: $rule.target) {
                                        ForEach(RouteTarget.allCases) { target in Text(target.title).tag(target) }
                                    }
                                    .labelsHidden().frame(width: 130)
                                    Button(role: .destructive) { removeApplication(rule) } label: {
                                        Image(systemName: "trash").foregroundStyle(.secondary)
                                    }
                                    .buttonStyle(.plain).help("Удалить правило и его маршруты")
                                }

                                HStack(spacing: 8) {
                                    Button {
                                        if collectingRuleID == rule.id { stopCollection() }
                                        else { startCollection(for: rule) }
                                    } label: {
                                        Label(collectingRuleID == rule.id ? "Остановить сбор" : "Собирать IP",
                                              systemImage: collectingRuleID == rule.id ? "stop.fill" : "dot.radiowaves.left.and.right")
                                    }
                                    .buttonStyle(.bordered)

                                    Button { scanOnce(for: rule) } label: {
                                        Label("Обновить IP", systemImage: "arrow.clockwise")
                                    }
                                    .buttonStyle(.bordered)

                                    Button { applyObservedIPs(for: rule) } label: {
                                        if isApplyingRuleID == rule.id { ProgressView().controlSize(.small) }
                                        else { Label("Применить IP (\(observedIPs[rule.bundleID, default: []].count))", systemImage: "arrow.triangle.branch") }
                                    }
                                    .buttonStyle(.borderedProminent)
                                    .disabled(observedIPs[rule.bundleID, default: []].isEmpty || isApplyingRuleID != nil)
                                }

                                if collectingRuleID == rule.id {
                                    Text("Сбор активен. Используйте выбранное приложение, чтобы появились IP.")
                                        .font(.caption).foregroundStyle(.blue)
                                }

                                let addresses = observedIPs[rule.bundleID, default: []]
                                if addresses.isEmpty {
                                    Text("IP ещё не собраны. Запустите сбор, затем используйте приложение.")
                                        .font(.caption).foregroundStyle(.secondary)
                                } else {
                                    Text("Найдено IP: \(addresses.count) · \(addresses.joined(separator: ", "))")
                                        .font(.caption.monospaced()).foregroundStyle(.secondary)
                                        .lineLimit(2).textSelection(.enabled)
                                    Button("Очистить IP и маршруты") { clearLearnedIPs(for: rule) }
                                        .buttonStyle(.link).font(.caption)
                                }
                            }
                            .padding(14)
                            .background(.background, in: RoundedRectangle(cornerRadius: 14))
                            .overlay(RoundedRectangle(cornerRadius: 14).stroke(.quaternary, lineWidth: 1))
                        }
                    }
                }
                Label {
                    Text("Сбор определяет внешние IP активных соединений выбранного приложения. Маршрут задаётся по IP на уровне macOS, поэтому он может затронуть и другие приложения, если они используют тот же адрес. Приложения, передающие сеть отдельному помощнику, могут не попасть в сбор.")
                        .fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(systemName: "info.circle.fill").foregroundStyle(.blue)
                }
                .font(.caption).foregroundStyle(.secondary)
                HStack {
                    Button(action: exportApps) { Label("Экспортировать правила приложений", systemImage: "square.and.arrow.up") }
                        .buttonStyle(.bordered)
                    Spacer()
                    if !appliedRoutes.isEmpty {
                        Button(role: .destructive, action: removeAllAppRoutes) {
                            Label("Убрать маршруты (\(appliedRoutes.count))", systemImage: "trash")
                        }
                        .buttonStyle(.bordered)
                        .disabled(isRemovingRoutes || isApplyingRuleID != nil)
                    }
                }
            }
            .padding(24).frame(maxWidth: 780, alignment: .leading).frame(maxWidth: .infinity)
        }
        .overlay(alignment: .bottom) {
            if let statusMessage {
                Text(statusMessage).font(.callout.weight(.medium)).foregroundStyle(.white)
                    .padding(.horizontal, 16).padding(.vertical, 10)
                    .background(.black.opacity(0.82), in: Capsule()).padding(.bottom, 14)
            }
        }
        .onAppear {
            rules = PolicyCodec.decode(storedRules, as: [AppRule].self) ?? []
            observedIPs = PolicyCodec.decode(storedObservedIPs, as: [String: [String]].self) ?? [:]
            appliedRoutes = PolicyCodec.decode(storedAppliedRoutes, as: [AppliedRoute].self) ?? []
            refreshInterfaces()
        }
        .onChange(of: rules) { _ in storedRules = PolicyCodec.encode(rules) ?? "[]" }
        .onChange(of: observedIPs) { _ in storedObservedIPs = PolicyCodec.encode(observedIPs) ?? "{}" }
        .onChange(of: appliedRoutes) { _ in storedAppliedRoutes = PolicyCodec.encode(appliedRoutes) ?? "[]" }
        .overlay {
            if isShowingAppPicker {
                applicationPicker
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(Color(nsColor: .windowBackgroundColor))
            }
        }
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button { navigate(.dashboard) } label: { Label("Главная", systemImage: "house") }
                Button { navigate(.sites) } label: { Label("Правила сайтов", systemImage: "globe") }
            }
        }
    }

    private var applicationPicker: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Выберите активное приложение").font(.headline)
                    Text("Правило будет создано для этой запущенной программы.").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button { refreshActiveApplications() } label: { Label("Обновить список", systemImage: "arrow.clockwise") }
                    .buttonStyle(.bordered)
            }
            TextField("Поиск приложения", text: $appSearchText)
                .textFieldStyle(.roundedBorder)
            if filteredApplications.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "app.dashed").font(.system(size: 28)).foregroundStyle(.secondary)
                    Text("Нет активных приложений").font(.headline)
                    Text("Запустите нужное приложение и обновите список.").font(.caption).foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(filteredApplications) { application in
                    Button { addApplication(application) } label: {
                        HStack(spacing: 10) {
                            Image(nsImage: NSWorkspace.shared.icon(forFile: application.path))
                                .resizable().frame(width: 30, height: 30)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(application.name).font(.body.weight(.medium))
                                Text(application.bundleID).font(.caption.monospaced()).foregroundStyle(.secondary)
                            }
                            Spacer()
                            if rules.contains(where: { $0.bundleID == application.bundleID }) {
                                Text("Добавлено").font(.caption).foregroundStyle(.secondary)
                            } else {
                                Image(systemName: "plus.circle.fill").foregroundStyle(.blue)
                            }
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .disabled(rules.contains(where: { $0.bundleID == application.bundleID }))
                }
                .listStyle(.inset)
            }
            HStack {
                Spacer()
                Button("Готово") { isShowingAppPicker = false }
                    .keyboardShortcut(.cancelAction)
            }
        }
        .padding(18)
        .frame(minWidth: 520, minHeight: 420)
        .onAppear(perform: refreshActiveApplications)
    }

    private func refreshActiveApplications() {
        activeApplications = NSWorkspace.shared.runningApplications.compactMap { application in
            guard application.activationPolicy == .regular,
                  let bundleID = application.bundleIdentifier,
                  let path = application.bundleURL?.path,
                  bundleID != Bundle.main.bundleIdentifier else { return nil }
            let name = application.localizedName
                ?? Bundle(url: URL(fileURLWithPath: path))?.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String
                ?? URL(fileURLWithPath: path).deletingPathExtension().lastPathComponent
            return RunningApplicationChoice(name: name, bundleID: bundleID, path: path)
        }
        .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    private func addApplication(_ application: RunningApplicationChoice) {
        guard !rules.contains(where: { $0.bundleID == application.bundleID }) else {
            statusMessage = "Это приложение уже добавлено."
            return
        }
        rules.append(AppRule(name: application.name, bundleID: application.bundleID, path: application.path, target: .tunnel))
        appSearchText = ""
        isShowingAppPicker = false
    }

    private func refreshInterfaces() {
        interfaces = InterfaceScanner.scan()
        let availableTunnels = interfaces.filter(\.isTunnel)
        if !availableTunnels.contains(where: { $0.name == selectedInterface }) {
            manuallySelectedInterface = false
        }
        if !manuallySelectedInterface {
            selectedInterface = TunnelSelector.preferredName(from: availableTunnels) ?? ""
        }
        gateways = GatewayScanner.scan(interfaces: interfaces)
    }

    private func startCollection(for rule: AppRule) {
        stopCollection()
        collectingRuleID = rule.id
        collectionTask = Task { @MainActor in
            while !Task.isCancelled {
                let processIDs = NSRunningApplication.runningApplications(withBundleIdentifier: rule.bundleID)
                    .map(\.processIdentifier)
                let found = await Task.detached(priority: .utility) {
                    ProcessConnectionScanner.scan(processIDs: processIDs)
                }.value
                merge(found, for: rule)
                do { try await Task.sleep(nanoseconds: 2_000_000_000) }
                catch { break }
            }
            if collectingRuleID == rule.id { collectingRuleID = nil }
        }
    }

    private func stopCollection() {
        collectionTask?.cancel()
        collectionTask = nil
        collectingRuleID = nil
    }

    private func scanOnce(for rule: AppRule) {
        let processIDs = NSRunningApplication.runningApplications(withBundleIdentifier: rule.bundleID)
            .map(\.processIdentifier)
        guard !processIDs.isEmpty else {
            statusMessage = "Приложение сейчас не запущено. Откройте его и повторите сбор."
            return
        }
        Task { @MainActor in
            let found = await Task.detached(priority: .userInitiated) {
                ProcessConnectionScanner.scan(processIDs: processIDs)
            }.value
            merge(found, for: rule)
            statusMessage = found.isEmpty
                ? "Активные внешние IP не найдены. Используйте приложение и запустите сбор трафика."
                : "Найдено новых или активных IP: \(found.count)."
        }
    }

    private func merge(_ addresses: [String], for rule: AppRule) {
        guard !addresses.isEmpty else { return }
        let merged = Set(observedIPs[rule.bundleID, default: []]).union(addresses).sorted()
        observedIPs[rule.bundleID] = Array(merged.prefix(256))
    }

    private func applyObservedIPs(for rule: AppRule) {
        refreshInterfaces()
        let addresses = observedIPs[rule.bundleID, default: []]
        guard !addresses.isEmpty else { return }
        let tunnel = activeTunnel
        guard rule.target == .direct || tunnel != nil else {
            statusMessage = "Активный VPN-туннель не найден. Подключите VPN и повторите."
            return
        }

        isApplyingRuleID = rule.id
        Task { @MainActor in
            var desiredRoutes: [AppliedRoute] = []
            var pending: [PendingRoute] = []
            var alreadyCorrect = 0
            var missingGateway = 0
            let previousRoutes = appliedRoutes.filter { $0.ruleID == rule.id }

            for rawAddress in addresses {
                guard let destination = ParsedDestination.parse(rawAddress),
                      destination.prefix == (destination.isIPv6 ? 128 : 32) else { continue }
                let directGateway = rule.target == .direct ? gateways.first(where: { $0.isIPv6 == destination.isIPv6 }) : nil
                if rule.target == .direct && directGateway == nil {
                    missingGateway += 1
                    continue
                }
                let routeInterface = rule.target == .tunnel ? (tunnel?.name ?? "") : (directGateway?.interface ?? "")
                let routeGateway = directGateway?.address
                let identifier = "app|\(rule.id)|\(destination.routeValue)|\(routeInterface)|\(routeGateway ?? "")"
                let route = AppliedRoute(id: identifier, ruleID: rule.id, destination: destination.routeValue,
                                         isIPv6: destination.isIPv6, interface: routeInterface, gateway: routeGateway)
                desiredRoutes.append(route)

                if RouteStateReader.alreadyMatches(destination, target: rule.target,
                                                   tunnelName: tunnel?.name ?? selectedInterface, directGateway: directGateway) {
                    alreadyCorrect += 1
                    continue
                }
                let previous = previousRoutes.first(where: { $0.destination == route.destination })
                if let previous {
                    pending.append(PendingRoute(id: route.id,
                                                command: previous.command(action: "change").command,
                                                fallbackCommand: route.command(action: "add").command))
                } else {
                    pending.append(route.command(action: "add"))
                }
            }

            if pending.isEmpty {
                isApplyingRuleID = nil
                statusMessage = missingGateway == 0
                    ? "IP-маршруты уже соответствуют правилу (\(alreadyCorrect))."
                    : "Для части IP не найден сетевой шлюз."
                return
            }

            do {
                let successful = try ElevatedRouteRunner.run(pending)
                let pendingIDs = Set(pending.map(\.id))
                let succeededRoutes = desiredRoutes.filter { successful.contains($0.id) }
                appliedRoutes.removeAll { old in
                    old.ruleID == rule.id && succeededRoutes.contains(where: { $0.destination == old.destination })
                }
                appliedRoutes.append(contentsOf: succeededRoutes.filter { route in
                    pendingIDs.contains(route.id) && successful.contains(route.id)
                })
                let failed = pending.count - successful.count
                statusMessage = failed == 0
                    ? "Применено IP-маршрутов: \(successful.count). Проверка правил обновится на главной."
                    : "Применено: \(successful.count), не удалось: \(failed). Возможно, часть IP уже занята другим маршрутом."
                if alreadyCorrect > 0 { statusMessage! += " Уже подходящих: \(alreadyCorrect)." }
                if missingGateway > 0 { statusMessage! += " Без шлюза: \(missingGateway)." }
            } catch {
                statusMessage = "Не удалось применить IP-маршруты. Разрешите системный запрос администратора и повторите."
            }
            isApplyingRuleID = nil
        }
    }

    private func removeApplication(_ rule: AppRule) {
        if collectingRuleID == rule.id { stopCollection() }
        rules.removeAll { $0.id == rule.id }
        clearLearnedIPs(for: rule)
    }

    private func clearLearnedIPs(for rule: AppRule) {
        let routes = appliedRoutes.filter { $0.ruleID == rule.id }
        observedIPs.removeValue(forKey: rule.bundleID)
        guard !routes.isEmpty else {
            statusMessage = "Собранные IP очищены."
            return
        }
        Task { @MainActor in
            do {
                let removed = try ElevatedRouteRunner.run(routes.map { $0.command(action: "delete") })
                appliedRoutes.removeAll { removed.contains($0.id) }
                if removed.count < routes.count {
                    statusMessage = "Удалены не все маршруты. Нажмите «Убрать маршруты» ниже."
                } else {
                    statusMessage = "Правило, найденные IP и его маршруты удалены."
                }
            } catch {
                statusMessage = "Правило удалено, но маршруты остались. Используйте «Убрать маршруты» ниже."
            }
        }
    }

    private func removeAllAppRoutes() {
        isRemovingRoutes = true
        Task { @MainActor in
            do {
                let removed = try ElevatedRouteRunner.run(appliedRoutes.map { $0.command(action: "delete") })
                appliedRoutes.removeAll { removed.contains($0.id) }
                statusMessage = appliedRoutes.isEmpty
                    ? "Маршруты приложений удалены."
                    : "Удалены доступные маршруты. Осталось: \(appliedRoutes.count)."
            } catch {
                statusMessage = "Не удалось удалить маршруты приложений."
            }
            isRemovingRoutes = false
        }
    }

    private func exportApps() {
        let panel = NSSavePanel()
        panel.title = "Сохранить правила приложений"
        panel.nameFieldStringValue = "vpn-app-rules.json"
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url,
              let data = try? JSONEncoder().encode(rules) else { return }
        do {
            try data.write(to: url, options: .atomic)
            statusMessage = "Правила приложений экспортированы."
        } catch {
            statusMessage = "Не удалось сохранить правила."
        }
    }
}

private struct PendingRoute {
    let id: String
    let command: String
    var fallbackCommand: String? = nil
}

private struct CurrentRoutePath {
    let interface: String?
    let gateway: String?
}

private enum RouteStateReader {
    static func alreadyMatches(
        _ destination: ParsedDestination,
        target: RouteTarget,
        tunnelName: String,
        directGateway: NetworkGateway?
    ) -> Bool {
        let hostPrefix = destination.isIPv6 ? 128 : 32
        guard destination.prefix == hostPrefix else { return false }
        return currentRouteMatches(destination, target: target, tunnelName: tunnelName, directGateway: directGateway)
    }

    static func currentRouteMatches(
        _ destination: ParsedDestination,
        target: RouteTarget,
        tunnelName: String,
        directGateway: NetworkGateway?
    ) -> Bool {
        guard let path = currentPath(to: destination) else { return false }
        switch target {
        case .tunnel:
            return path.interface == tunnelName
        case .direct:
            return directGateway.map { path.interface == $0.interface } ?? false
        }
    }

    private static func currentPath(to destination: ParsedDestination) -> CurrentRoutePath? {
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/sbin/route")
        process.arguments = ["-n", "get", destination.isIPv6 ? "-inet6" : "-inet", destination.address]
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            let data = output.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            guard process.terminationStatus == 0,
                  let text = String(data: data, encoding: .utf8) else { return nil }

            var interface: String?
            var gateway: String?
            for line in text.split(whereSeparator: \.isNewline) {
                let columns = line.split(separator: ":", maxSplits: 1).map(String.init)
                guard columns.count == 2 else { continue }
                let key = columns[0].trimmingCharacters(in: .whitespaces)
                let value = columns[1].trimmingCharacters(in: .whitespaces)
                if key == "interface" { interface = value }
                if key == "gateway" { gateway = value }
            }
            return CurrentRoutePath(interface: interface, gateway: gateway)
        } catch {
            return nil
        }
    }

}

private extension AppliedRoute {
    func command(action: String) -> PendingRoute {
        var arguments = ["/sbin/route", "-n", action]
        if isIPv6 { arguments.append("-inet6") }
        arguments += ["-net", destination]
        if let gateway {
            arguments.append(gateway)
        } else if !interface.isEmpty {
            arguments += ["-interface", interface]
        }
        let command = arguments.map(shellQuote).joined(separator: " ")
        return PendingRoute(id: id, command: command)
    }
}

private enum ElevatedRouteRunner {
    static func run(_ pending: [PendingRoute]) throws -> Set<String> {
        let scriptBody = pending.map { item in
            let success = shellQuote("OK|\(item.id)\\n")
            let failure = shellQuote("ERR|\(item.id)\\n")
            if let fallbackCommand = item.fallbackCommand {
                return "if \(item.command) >/dev/null 2>&1; then printf \(success); elif \(fallbackCommand) >/dev/null 2>&1; then printf \(success); else printf \(failure); fi"
            }
            return "if \(item.command) >/dev/null 2>&1; then printf \(success); else printf \(failure); fi"
        }
        .joined(separator: "; ")

        let source = "do shell script \(appleScriptQuote(scriptBody)) with administrator privileges"
        guard let script = NSAppleScript(source: source) else { throw RouteError.authorization }
        var errorInfo: NSDictionary?
        let result = script.executeAndReturnError(&errorInfo)
        if let errorInfo { throw RouteError.execution(errorInfo[NSAppleScript.errorMessage] as? String ?? "") }
        let output = result.stringValue ?? ""
        return Set(output.split(separator: "\n").compactMap { line in
            let parts = line.split(separator: "|", maxSplits: 1)
            guard parts.count == 2, parts[0] == "OK" else { return nil }
            return String(parts[1])
        })
    }
}

private enum RouteError: Error {
    case authorization
    case execution(String)
}

private func routeTargetIsValid(_ destination: ParsedDestination, rule: SiteRule, gateway: NetworkGateway?) -> Bool {
    if rule.target == .tunnel { return true }
    guard let gateway else { return false }
    return gateway.isIPv6 == destination.isIPv6
}

private func isSupportedDestination(_ value: String) -> Bool {
    if ParsedDestination.parse(value) != nil { return true }
    guard !value.contains("/") else { return false }
    let host = value.trimmingCharacters(in: CharacterSet(charactersIn: ". "))
    guard !host.isEmpty, host.count <= 253 else { return false }
    let labels = host.split(separator: ".", omittingEmptySubsequences: false)
    guard labels.count >= 2 else { return false }
    return labels.allSatisfy { label in
        !label.isEmpty && label.count <= 63 && label.first != "-" && label.last != "-"
            && label.unicodeScalars.allSatisfy { CharacterSet.alphanumerics.contains($0) || $0 == "-" }
    }
}

private func shellQuote(_ value: String) -> String {
    "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
}

private func stringFromBuffer(_ buffer: [CChar]) -> String {
    let length = buffer.firstIndex(of: 0) ?? buffer.endIndex
    return String(decoding: buffer[..<length].map { UInt8(bitPattern: $0) }, as: UTF8.self)
}

private func appleScriptQuote(_ value: String) -> String {
    "\"" + value
        .replacingOccurrences(of: "\\", with: "\\\\")
        .replacingOccurrences(of: "\"", with: "\\\"")
        .replacingOccurrences(of: "\n", with: "\\n") + "\""
}
