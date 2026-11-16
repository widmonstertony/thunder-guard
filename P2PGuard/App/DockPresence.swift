import AppKit
import SwiftUI

@MainActor final class DockPresence: NSObject, NSApplicationDelegate {
    private let windows = NSHashTable<NSWindow>.weakObjects()

    func applicationDidFinishLaunching(_ notification: Notification) {
        let center = NotificationCenter.default
        center.addObserver(self, selector: #selector(visible(_:)), name: NSWindow.didBecomeKeyNotification, object: nil)
        center.addObserver(self, selector: #selector(closing(_:)), name: NSWindow.willCloseNotification, object: nil)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func track(_ window: NSWindow) {
        windows.add(window)
        showDock()
    }

    @objc private func visible(_ notification: Notification) {
        if let window = notification.object as? NSWindow, windows.contains(window) { showDock() }
    }

    @objc private func closing(_ notification: Notification) {
        guard let window = notification.object as? NSWindow, windows.contains(window) else { return }
        update(excluding: window)
    }

    func update(excluding closing: NSWindow? = nil) {
        let menuEnabled = UserDefaults.standard.object(forKey: "showNetworkMenu") as? Bool ?? true
        let hasWindow = windows.allObjects.contains { $0 !== closing && ($0.isVisible || $0.isMiniaturized) }
        let policy: NSApplication.ActivationPolicy = menuEnabled && !hasWindow ? .accessory : .regular
        if NSApplication.shared.activationPolicy() != policy { NSApplication.shared.setActivationPolicy(policy) }
    }

    func showDock() {
        if NSApplication.shared.activationPolicy() != .regular { NSApplication.shared.setActivationPolicy(.regular) }
    }
}

struct DockWindowAnchor: NSViewRepresentable {
    let dock: DockPresence
    func makeNSView(context: Context) -> Anchor { Anchor(dock) }
    func updateNSView(_ view: Anchor, context: Context) {}

    final class Anchor: NSView {
        weak var dock: DockPresence?
        init(_ dock: DockPresence) { self.dock = dock; super.init(frame: .zero) }
        required init?(coder: NSCoder) { nil }
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            if let window { dock?.track(window) }
        }
    }
}
