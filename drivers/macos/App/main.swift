// Avulse.app: installs the avulse system extension and turns its packet filter on or off.
//
//   Avulse.app/Contents/MacOS/Avulse install     activate the extension, then enable the filter
//   Avulse.app/Contents/MacOS/Avulse uninstall   disable the filter, then deactivate the extension
//   Avulse.app/Contents/MacOS/Avulse status      the filter's configuration
//
// The app must be in /Applications, and the first install asks the user to approve the
// extension (System Settings, Login Items & Extensions) and the filter. Prints `RESULT ...`
// lines and exits 0 on success.

import Foundation
import NetworkExtension
import SystemExtensions

let extensionId = "com.github.ffalcinelli.avulse.extension"

func finish(_ code: Int32, _ message: String) -> Never {
    print("RESULT \(message)")
    exit(code)
}

func setFilter(enabled: Bool, then: @escaping () -> Void) {
    let m = NEFilterManager.shared()
    m.loadFromPreferences { err in
        if let err = err { finish(3, "load-preferences failed: \(err)") }
        if enabled {
            let c = NEFilterProviderConfiguration()
            c.filterPackets = true
            c.filterPacketProviderBundleIdentifier = extensionId
            // Flows and sockets (the FLOW and SOCKET layers), from the same extension.
            c.filterSockets = true
            c.filterDataProviderBundleIdentifier = extensionId
            m.providerConfiguration = c
            m.localizedDescription = "Avulse"
        }
        m.isEnabled = enabled
        m.saveToPreferences { err in
            if let err = err as NSError? {
                finish(4, "filter save failed: domain=\(err.domain) code=\(err.code) \(err)")
            }
            then()
        }
    }
}

class Delegate: NSObject, OSSystemExtensionRequestDelegate {
    let onDone: () -> Void

    init(onDone: @escaping () -> Void) { self.onDone = onDone }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        return .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        print("RESULT needs-user-approval: System Settings, Login Items & Extensions")
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        onDone()
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        let e = error as NSError
        finish(2, "failed: domain=\(e.domain) code=\(e.code) \(e.localizedDescription)")
    }
}

setvbuf(stdout, nil, _IOLBF, 0)
var delegate: Delegate?
switch CommandLine.arguments.dropFirst().first {
case "install":
    delegate = Delegate {
        setFilter(enabled: true) { finish(0, "installed") }
    }
    let r = OSSystemExtensionRequest.activationRequest(
        forExtensionWithIdentifier: extensionId, queue: .main)
    r.delegate = delegate
    OSSystemExtensionManager.shared.submitRequest(r)
case "uninstall":
    setFilter(enabled: false) {
        delegate = Delegate { finish(0, "uninstalled") }
        let r = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: extensionId, queue: .main)
        r.delegate = delegate
        OSSystemExtensionManager.shared.submitRequest(r)
    }
case "status":
    NEFilterManager.shared().loadFromPreferences { err in
        let m = NEFilterManager.shared()
        finish(
            err == nil ? 0 : 3,
            "enabled=\(m.isEnabled) configuration=\(String(describing: m.providerConfiguration))")
    }
default:
    finish(1, "usage: Avulse install | uninstall | status")
}
dispatchMain()
