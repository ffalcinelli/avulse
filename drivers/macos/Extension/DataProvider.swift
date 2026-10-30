// The flow provider: every new socket flow goes through the Rust logic, which reports it to the
// SOCKET handles (a connect or an accept, which one without SNIFF refuses) and the FLOW handles,
// and says whether it wants the flow's end, which comes back as a report (shouldReport), so
// that no data is peeked at.

import Foundation
import NetworkExtension
import os

private let log = Logger(subsystem: "com.github.ffalcinelli.avulse", category: "flows")

class DataProvider: NEFilterDataProvider {
    private let lock = NSLock()
    /// The flows whose end the logic wants, by the system's identifier.
    private var ids: [UUID: UInt64] = [:]

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        avulse_ext_flows(true)
        log.notice("avulse data provider started")
        completionHandler(nil)
    }

    override func stopFilter(
        with reason: NEProviderStopReason, completionHandler: @escaping () -> Void
    ) {
        avulse_ext_flows(false)
        log.notice("avulse data provider stopped: \(reason.rawValue)")
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socket = flow as? NEFilterSocketFlow else { return .allow() }
        let local = socket.localEndpoint as? NWHostEndpoint
        let remote = socket.remoteEndpoint as? NWHostEndpoint
        var id: UInt64 = 0
        var watch = false
        let verdict = withAuditToken(flow.sourceAppAuditToken) { token in
            avulse_ext_flow_new(
                socket.direction == .outbound, UInt8(truncatingIfNeeded: socket.socketProtocol),
                local?.hostname ?? "", UInt16(local?.port ?? "") ?? 0,
                remote?.hostname ?? "", UInt16(remote?.port ?? "") ?? 0,
                token, &id, &watch)
        }
        if verdict == Int32(AVULSE_DROP) {
            return .drop()
        }
        let v = NEFilterNewFlowVerdict.allow()
        if watch {
            lock.lock()
            ids[flow.identifier] = id
            lock.unlock()
            v.shouldReport = true
        }
        return v
    }

    override func handle(_ report: NEFilterReport) {
        guard report.event == .flowClosed, let flow = report.flow else { return }
        lock.lock()
        let id = ids.removeValue(forKey: flow.identifier)
        lock.unlock()
        if let id = id {
            avulse_ext_flow_end(id)
        }
    }
}

/// `body` with the bytes of an audit token (`audit_token_t`, 32 bytes), or null.
private func withAuditToken<R>(_ data: Data?, _ body: (UnsafePointer<UInt8>?) -> R) -> R {
    guard let data = data, data.count >= 32 else { return body(nil) }
    return data.withUnsafeBytes { body($0.bindMemory(to: UInt8.self).baseAddress) }
}
