import AppKit
import SwiftUI

/// Hosted inside the fork's existing AppDelegate, not a second app process.
@objc(TGDashboardHost) @MainActor final class IntegratedDashboardHost: NSObject {
    @objc static let shared = IntegratedDashboardHost()
    private var controller: NSWindowController?

    @objc func show() {
        if controller == nil {
            let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1040, height: 780),
                                  styleMask: [.titled, .closable, .miniaturizable, .resizable],
                                  backing: .buffered, defer: false)
            window.title = "迅雷护栏"
            window.contentView = NSHostingView(rootView: IntegratedDashboard())
            window.isReleasedWhenClosed = false
            window.center()
            controller = NSWindowController(window: window)
        }
        NSApp.setActivationPolicy(.regular)
        controller?.showWindow(nil)
        controller?.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
}

private struct IntegratedDashboard: View {
    @StateObject private var protection = ProtectionStore()
    @State private var magnet = false

    var body: some View {
        NetworkDashboardView(showProtectionDetails: { TGNativeBridge.showRules() })
            .environmentObject(protection)
            .toolbar {
                Button("管理规则", systemImage: "slider.horizontal.3") { TGNativeBridge.showRules() }
                Button("添加到云盘", systemImage: "cloud.badge.plus") { magnet = true }
            }
            .sheet(isPresented: $magnet) {
                VStack {
                    HStack { Spacer(); Button("完成") { magnet = false } }
                    CloudMagnetView()
                }.padding().frame(width: 700, height: 620)
            }
            .onAppear { protection.refresh() }
            .onReceive(Timer.publish(every: 15, on: .main, in: .common).autoconnect()) { _ in
                protection.refresh()
            }
    }
}
