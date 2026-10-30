// The C interface of avulse's system extension logic (crates/macos-ext, a Rust static
// library), for the Swift shim. See the crate's documentation for what each call does.
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// What the packet path says to do with a packet.
enum { AVULSE_ALLOW = 0, AVULSE_DROP = 1, AVULSE_DELAY = 2 };

// Sets the extension up. `release(token, allow)` says what becomes of a held packet.
bool avulse_ext_init(void (*release)(uint64_t token, bool allow), bool test_mode);

// The verdict for a packet; for AVULSE_DELAY, `*token` is what to hold it under.
int32_t avulse_ext_packet(uint32_t ifindex, const char *ifname, bool outbound, bool loopback,
                          const uint8_t *data, size_t len, uint64_t *token);

// Serves a request from a client connection (its effective user and process); free the
// response with avulse_ext_free. A receive request waits: call it off the connection's queue.
uint8_t *avulse_ext_request(uint64_t conn, uint32_t euid, uint32_t pid, const uint8_t *req,
                            size_t len, size_t *out_len);
void avulse_ext_free(uint8_t *p, size_t len);

// A client connection went away: its handles close.
void avulse_ext_disconnect(uint64_t conn);

// Whether the data provider runs (the FLOW and SOCKET layers need it).
void avulse_ext_flows(bool on);

// A new flow: AVULSE_ALLOW or AVULSE_DROP; `*id` names it, and `*watch` says whether to report
// its end. The hosts are numeric addresses; the audit token is 32 bytes, or null.
int32_t avulse_ext_flow_new(bool outbound, uint8_t protocol, const char *local_host,
                            uint16_t local_port, const char *remote_host, uint16_t remote_port,
                            const uint8_t *audit_token, uint64_t *id, bool *watch);

// The end of a flow whose end avulse_ext_flow_new wanted.
void avulse_ext_flow_end(uint64_t id);
