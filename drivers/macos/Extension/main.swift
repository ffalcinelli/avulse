// The avulse system extension. With `--test`, it serves its XPC service without the packet
// provider (and so without the Network Extension framework's approval), and takes test packets
// instead: what the runners can run. `--service NAME` changes the service's name.

import Foundation
import NetworkExtension

let arguments = CommandLine.arguments
let testMode = arguments.contains("--test")
var service = "group.com.github.ffalcinelli.avulse"
if let ne = Bundle.main.object(forInfoDictionaryKey: "NetworkExtension") as? [String: Any],
    let name = ne["NEMachServiceName"] as? String
{
    service = name
}
if let i = arguments.firstIndex(of: "--service"), i + 1 < arguments.count {
    service = arguments[i + 1]
}

Held.shared.testMode = testMode
_ = avulse_ext_init({ token, allow in Held.shared.release(token, allow) }, testMode)
Service.shared.start(name: service)
if !testMode {
    autoreleasepool {
        NEProvider.startSystemExtensionMode()
    }
}
dispatchMain()
