// The packet filter provider: every packet goes through the Rust bytecode interpreter. A match
// is delayed and then allowed again from another queue, which is how a diverting handle would
// hold a packet and give it back unmodified (NEFilterPacketProvider cannot inject new bytes).
// It logs the first packets it sees on each interface (direction, length, leading bytes: do they
// start with an Ethernet header?) and, every two seconds, how many packets and bytes it handled,
// per interface, and how long delayed packets waited before `allow` returned.

import Foundation
import Network
import NetworkExtension
import os

private let log = Logger(subsystem: "com.github.ffalcinelli.avulse.spike", category: "filter")

class FilterPacketProvider: NEFilterPacketProvider {
    private var program = [UInt8](repeating: 0, count: 65536)
    private let queue = DispatchQueue(label: "avulse.reinject")
    private let lock = NSLock()
    private var packets = 0
    private var bytes = 0
    private var delayed = 0
    private var perInterface: [String: Int] = [:]
    private var delayNanos: UInt64 = 0
    private var timer: DispatchSourceTimer?

    /// Counts a packet; returns how many the interface has seen, this one included.
    private func count(_ length: Int, interface: String, delayed d: Bool) -> Int {
        lock.lock()
        defer { lock.unlock() }
        packets += 1
        bytes += length
        if d { delayed += 1 }
        let n = (perInterface[interface] ?? 0) + 1
        perInterface[interface] = n
        return n
    }

    private func allow(_ packet: NEPacket, since start: UInt64) {
        allow(packet)
        let waited = DispatchTime.now().uptimeNanoseconds - start
        lock.lock()
        delayNanos += waited
        lock.unlock()
    }

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        let src = Array("tcp.dstport == 443".utf8)
        let n = avulse_spike_compile(src, src.count, &program, program.count)
        guard n > 0 else {
            log.error("AVULSE compile failed: \(n)")
            completionHandler(NSError(domain: "avulse", code: Int(n)))
            return
        }
        let prog = Array(program[0..<Int(n)])
        log.notice("AVULSE start: \(n) bytes of bytecode")
        packetHandler = { [weak self] context, interface, direction, bytes, length in
            guard let self = self else { return .allow }
            // The handler is told nothing about the link type: try both and log which parses.
            let hit = prog.withUnsafeBufferPointer { p in
                avulse_spike_matches(
                    p.baseAddress, p.count, bytes.assumingMemoryBound(to: UInt8.self), length,
                    0, direction == .outbound)
            }
            let name = String(cString: nw_interface_get_name(interface))
            let n = self.count(length, interface: name, delayed: hit == 1)
            if n <= 5 {
                let kind = nw_interface_get_type(interface).rawValue
                let head = UnsafeRawBufferPointer(start: bytes, count: min(length, 48))
                    .map { String(format: "%02x", $0) }.joined()
                log.notice(
                    "AVULSE packet \(n) if=\(name, privacy: .public) type=\(kind) dir=\(direction.rawValue) len=\(length) match=\(hit) bytes=\(head, privacy: .public)"
                )
            }
            guard hit == 1 else { return .allow }
            let start = DispatchTime.now().uptimeNanoseconds
            let packet = self.delayCurrentPacket(context)
            self.queue.async { self.allow(packet, since: start) }
            return .delay
        }
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + 2, repeating: 2)
        t.setEventHandler { [weak self] in
            guard let self = self else { return }
            self.lock.lock()
            let (p, b, d) = (self.packets, self.bytes, self.delayed)
            let per = self.perInterface.map { "\($0.key):\($0.value)" }.sorted().joined(separator: ",")
            let avg = d > 0 ? self.delayNanos / UInt64(d) : 0
            self.lock.unlock()
            log.notice(
                "AVULSE totals packets=\(p) bytes=\(b) delayed=\(d) avg_delay_ns=\(avg) per_interface=\(per, privacy: .public)"
            )
        }
        t.resume()
        timer = t
        completionHandler(nil)
    }

    override func stopFilter(
        with reason: NEProviderStopReason, completionHandler: @escaping () -> Void
    ) {
        log.notice("AVULSE stop: \(reason.rawValue)")
        timer?.cancel()
        packetHandler = nil
        completionHandler()
    }
}
