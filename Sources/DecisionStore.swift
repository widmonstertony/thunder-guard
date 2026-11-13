import Foundation
import SwiftUI

struct ConnectionDecision: Identifiable {
    let id = UUID()
    let time: Date
    let processPath: String
    let address: String
    let port: String
    let blocked: Bool

    var appName: String {
        if processPath.contains("/Thunder.app/") { return "迅雷下载服务" }
        return URL(fileURLWithPath: processPath).deletingPathExtension().lastPathComponent
    }
}

/// Keeps only decision metadata in memory. The stream predicate excludes URL
/// detail records, which may contain signed download URLs or authentication data.
final class DecisionStore: ObservableObject {
    @Published var blocked: [ConnectionDecision] = []
    @Published var error: String?
    @Published var listening = false
    private var task: Process?
    private var pipe: Pipe?
    private var generation = UUID()

    func start() {
        guard task == nil else { return }
        let token = UUID()
        generation = token
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/log")
        process.arguments = ["stream", "--level", "debug", "--style", "compact", "--predicate",
            "subsystem == \"com.objective-see.lulu\" AND eventMessage CONTAINS \"[LULU] PROCESS:\""]
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            task = process
            pipe = output
            listening = true
            error = nil
            DispatchQueue.global(qos: .utility).async { [weak self] in
                var pending = Data()
                let handle = output.fileHandleForReading
                while process.isRunning {
                    let chunk = handle.availableData
                    if chunk.isEmpty { break }
                    pending.append(chunk)
                    while let end = pending.firstIndex(of: 10) {
                        let line = String(decoding: pending[..<end], as: UTF8.self)
                        pending.removeSubrange(...end)
                        guard let item = Self.parse(line), item.blocked else { continue }
                        DispatchQueue.main.async {
                            guard let self, self.generation == token else { return }
                            self.blocked.insert(item, at: 0)
                            if self.blocked.count > 200 { self.blocked.removeLast(self.blocked.count - 200) }
                        }
                    }
                    // Bound memory even if a malformed log has no line break.
                    if pending.count > 131_072 { pending.removeAll(keepingCapacity: true) }
                }
                DispatchQueue.main.async {
                    guard let self, self.generation == token else { return }
                    self.task = nil
                    self.pipe = nil
                    self.listening = false
                    self.error = "拦截记录流已停止；点击重试。"
                }
            }
        } catch {
            self.error = "无法读取 LuLu 的实时拦截记录。"
        }
    }

    func stop() {
        generation = UUID()
        task?.terminate()
        task = nil
        pipe = nil
        listening = false
    }

    static func parse(_ line: String) -> ConnectionDecision? {
        guard let start = line.range(of: "[LULU] PROCESS: "),
              let flow = line.range(of: ", FLOW (endpoint): ", range: start.upperBound..<line.endIndex),
              let rule = line.range(of: ", RULE:", range: flow.upperBound..<line.endIndex),
              let verdict = line.range(of: "verdict: ", options: .backwards),
              let result = line[verdict.upperBound...].first, result == "0" || result == "1" else { return nil }
        let processPath = String(line[start.upperBound..<flow.lowerBound])
        let endpoint = String(line[flow.upperBound..<rule.lowerBound])
        guard processPath.hasPrefix("/"), endpoint.count < 512,
              let divider = endpoint.lastIndex(where: { $0 == ":" || $0 == "." }) else { return nil }
        let port = String(endpoint[endpoint.index(after: divider)...])
        guard let number = Int(port), (1...65535).contains(number) else { return nil }
        return ConnectionDecision(time: Date(), processPath: processPath,
                                  address: String(endpoint[..<divider]), port: port, blocked: result == "1")
    }

    deinit { task?.terminate() }
}
