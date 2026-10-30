// The packets the provider holds (delayCurrentPacket), by the token the Rust logic gave them,
// until it says what becomes of each: allow it, or drop it (releasing a delayed packet drops
// it). The release may come before the packet is stored, from another thread: it waits here.

import Foundation
import NetworkExtension

final class Held {
    static let shared = Held()

    weak var provider: NEFilterPacketProvider?
    /// Without the provider (`--test`), nothing is held, and releases are ignored.
    var testMode = false
    private let lock = NSLock()
    private var packets: [UInt64: NEPacket] = [:]
    private var early: [UInt64: Bool] = [:]

    func store(_ token: UInt64, _ packet: NEPacket) {
        lock.lock()
        if let allow = early.removeValue(forKey: token) {
            lock.unlock()
            finish(packet, allow)
            return
        }
        packets[token] = packet
        lock.unlock()
    }

    func release(_ token: UInt64, _ allow: Bool) {
        if testMode {
            return
        }
        lock.lock()
        if let packet = packets.removeValue(forKey: token) {
            lock.unlock()
            finish(packet, allow)
            return
        }
        early[token] = allow
        lock.unlock()
    }

    private func finish(_ packet: NEPacket, _ allow: Bool) {
        if allow {
            provider?.allow(packet)
        }
    }
}
