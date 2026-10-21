// The packet filter provider: every packet goes through the Rust bytecode interpreter. A match
// is delayed and then allowed again from another queue, which is how a diverting handle would
// hold a packet and give it back unmodified (NEFilterPacketProvider cannot inject new bytes).

import Foundation
import Network
import NetworkExtension

class FilterPacketProvider: NEFilterPacketProvider {
    private var program = [UInt8](repeating: 0, count: 65536)
    private let queue = DispatchQueue(label: "avulse.reinject")

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        let src = Array("tcp.dstport == 443".utf8)
        let n = avulse_spike_compile(src, src.count, &program, program.count)
        guard n > 0 else {
            completionHandler(NSError(domain: "avulse", code: Int(n)))
            return
        }
        let prog = Array(program[0..<Int(n)])
        packetHandler = { [weak self] context, _, direction, bytes, length in
            let hit = prog.withUnsafeBufferPointer { p in
                avulse_spike_matches(
                    p.baseAddress, p.count, bytes.assumingMemoryBound(to: UInt8.self), length,
                    0, direction == .outbound)
            }
            guard hit == 1, let self = self else { return .allow }
            let packet = self.delayCurrentPacket(context)
            self.queue.async { self.allow(packet) }
            return .delay
        }
        completionHandler(nil)
    }

    override func stopFilter(
        with reason: NEProviderStopReason, completionHandler: @escaping () -> Void
    ) {
        packetHandler = nil
        completionHandler()
    }
}
