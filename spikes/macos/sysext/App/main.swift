// The host app: checks that the Rust library runs inside a Swift process, asks for the system
// extension to be activated, and, if that works, enables it as the packet filter and times a
// few HTTPS requests with and without it, plus pings on lo0 and the feth pair so that the
// provider logs which interfaces it sees. Prints `RESULT <outcome>` lines. activate.sh approves
// the extension and the filter while this waits (up to five minutes).

import Foundation
import NetworkExtension
import SystemExtensions

let extensionId = "com.github.ffalcinelli.avulse.spike.filter"

func selfTest() -> String {
    var prog = [UInt8](repeating: 0, count: 65536)
    let src = Array("tcp.dstport == 443".utf8)
    let n = avulse_spike_compile(src, src.count, &prog, prog.count)
    guard n > 0 else { return "compile failed: \(n)" }
    // An IPv4 SYN to port 443, then the same to port 80.
    var pkt: [UInt8] = [
        0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        0xc3, 0x50, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0,
    ]
    let hit = avulse_spike_matches(prog, Int(n), pkt, pkt.count, 1, true)
    pkt[23] = 80
    let miss = avulse_spike_matches(prog, Int(n), pkt, pkt.count, 1, true)
    return hit == 1 && miss == 0 ? "ok (\(n) bytes of bytecode)" : "wrong: \(hit) \(miss)"
}

/// Seconds for each of a few HTTPS requests.
func timeRequests(_ label: String) {
    var times: [String] = []
    for _ in 0..<5 {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        p.arguments = ["-sS", "-o", "/dev/null", "-w", "%{time_total}", "https://github.com/"]
        let out = Pipe()
        p.standardOutput = out
        try? p.run()
        p.waitUntilExit()
        let s = String(data: out.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)
        times.append(s ?? "?")
    }
    print("RESULT curl \(label): \(times.joined(separator: " "))")
}

func enableFilter() {
    let m = NEFilterManager.shared()
    m.loadFromPreferences { err in
        if let err = err { print("RESULT load-preferences failed: \(err)") }
        let c = NEFilterProviderConfiguration()
        c.filterPackets = true
        c.filterSockets = false
        c.filterPacketProviderBundleIdentifier = extensionId
        m.providerConfiguration = c
        m.localizedDescription = "Avulse spike"
        m.isEnabled = true
        m.saveToPreferences { err in
            if let err = err as NSError? {
                print("RESULT filter-save failed domain=\(err.domain) code=\(err.code) \(err)")
                exit(5)
            }
            print("RESULT filter-enabled")
            DispatchQueue.global().asyncAfter(deadline: .now() + 3) {
                timeRequests("with the filter")
                for host in ["127.0.0.1", "10.77.1.2"] {
                    let p = Process()
                    p.executableURL = URL(fileURLWithPath: "/sbin/ping")
                    p.arguments = ["-c", "3", "-t", "4", host]
                    try? p.run()
                    p.waitUntilExit()
                }
                // Let the provider log its totals.
                Thread.sleep(forTimeInterval: 3)
                m.isEnabled = false
                m.saveToPreferences { _ in exit(0) }
            }
        }
    }
}

class Delegate: NSObject, OSSystemExtensionRequestDelegate {
    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        return .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        // Keep waiting: the request may still complete if something approves it.
        print("RESULT needs-user-approval")
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        print("RESULT activated \(result.rawValue)")
        enableFilter()
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        let e = error as NSError
        print("RESULT failed domain=\(e.domain) code=\(e.code) \(e.localizedDescription)")
        exit(1)
    }
}

setvbuf(stdout, nil, _IOLBF, 0)
print("SELFTEST \(selfTest())")
timeRequests("without the filter")
let delegate = Delegate()
let request = OSSystemExtensionRequest.activationRequest(
    forExtensionWithIdentifier: extensionId, queue: .main)
request.delegate = delegate
OSSystemExtensionManager.shared.submitRequest(request)
DispatchQueue.main.asyncAfter(deadline: .now() + 300) {
    print("RESULT timeout")
    exit(4)
}
dispatchMain()
