// The XPC Mach service that the avulse library talks to: each request goes to the Rust logic,
// on a concurrent queue (a receive waits), and its end closes the connection's handles.

import Foundation

final class Service {
    static let shared = Service()

    private var listener: xpc_connection_t?
    private let lock = NSLock()
    private var nextConnection: UInt64 = 1
    private let requests = DispatchQueue(label: "avulse.requests", attributes: .concurrent)

    func start(name: String) {
        let listener = xpc_connection_create_mach_service(
            name, nil, UInt64(XPC_CONNECTION_MAKE_LISTENER))
        xpc_connection_set_event_handler(listener) { peer in
            if xpc_get_type(peer) == XPC_TYPE_CONNECTION {
                self.accept(peer)
            }
        }
        xpc_connection_resume(listener)
        self.listener = listener
    }

    private func accept(_ peer: xpc_connection_t) {
        lock.lock()
        let id = nextConnection
        nextConnection += 1
        lock.unlock()
        let euid = xpc_connection_get_euid(peer)
        xpc_connection_set_event_handler(peer) { message in
            if xpc_get_type(message) == XPC_TYPE_ERROR {
                avulse_ext_disconnect(id)
                return
            }
            guard xpc_get_type(message) == XPC_TYPE_DICTIONARY else { return }
            self.requests.async {
                var length = 0
                let data = xpc_dictionary_get_data(message, "d", &length)
                var outLength = 0
                guard
                    let out = avulse_ext_request(
                        id, euid, data?.assumingMemoryBound(to: UInt8.self), length, &outLength)
                else { return }
                if let reply = xpc_dictionary_create_reply(message) {
                    xpc_dictionary_set_data(reply, "d", out, outLength)
                    xpc_connection_send_message(peer, reply)
                }
                avulse_ext_free(out, outLength)
            }
        }
        xpc_connection_resume(peer)
    }
}
