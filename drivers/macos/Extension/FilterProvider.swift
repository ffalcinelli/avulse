// The packet provider: every packet goes through the Rust logic, which says to allow, drop or
// hold it (a diverted packet, until its handle sends it back or drops it).

import Foundation
import Network
import NetworkExtension
import os

private let log = Logger(subsystem: "com.github.ffalcinelli.avulse", category: "provider")

class FilterProvider: NEFilterPacketProvider {
    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        Held.shared.provider = self
        packetHandler = { [weak self] context, interface, direction, bytes, length in
            guard let self = self else { return .allow }
            var token: UInt64 = 0
            let verdict = avulse_ext_packet(
                nw_interface_get_index(interface), nw_interface_get_name(interface),
                direction == .outbound, nw_interface_get_type(interface) == nw_interface_type_loopback,
                bytes.assumingMemoryBound(to: UInt8.self), length, &token)
            switch verdict {
            case Int32(AVULSE_DROP):
                return .drop
            case Int32(AVULSE_DELAY):
                Held.shared.store(token, self.delayCurrentPacket(context))
                return .delay
            default:
                return .allow
            }
        }
        log.notice("avulse packet provider started")
        completionHandler(nil)
    }

    override func stopFilter(
        with reason: NEProviderStopReason, completionHandler: @escaping () -> Void
    ) {
        log.notice("avulse packet provider stopped: \(reason.rawValue)")
        packetHandler = nil
        completionHandler()
    }
}
