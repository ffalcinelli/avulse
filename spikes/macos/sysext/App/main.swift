// The host app: checks that the Rust library runs inside a Swift process, then asks for the
// system extension to be activated and prints how the request ends, as `RESULT <outcome>`.

import Foundation
import SystemExtensions

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

class Delegate: NSObject, OSSystemExtensionRequestDelegate {
    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        return .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        print("RESULT needs-user-approval")
        exit(3)
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        print("RESULT finished \(result.rawValue)")
        exit(0)
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        let e = error as NSError
        print("RESULT failed domain=\(e.domain) code=\(e.code) \(e.localizedDescription)")
        exit(1)
    }
}

print("SELFTEST \(selfTest())")
let delegate = Delegate()
let request = OSSystemExtensionRequest.activationRequest(
    forExtensionWithIdentifier: "com.github.ffalcinelli.avulse.spike.filter", queue: .main)
request.delegate = delegate
OSSystemExtensionManager.shared.submitRequest(request)
DispatchQueue.main.asyncAfter(deadline: .now() + 30) {
    print("RESULT timeout")
    exit(4)
}
dispatchMain()
