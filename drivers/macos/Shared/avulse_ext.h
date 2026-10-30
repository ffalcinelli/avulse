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

// Serves a request from a client connection; free the response with avulse_ext_free. A receive
// request waits: call it off the connection's queue.
uint8_t *avulse_ext_request(uint64_t conn, uint32_t euid, const uint8_t *req, size_t len,
                            size_t *out_len);
void avulse_ext_free(uint8_t *p, size_t len);

// A client connection went away: its handles close.
void avulse_ext_disconnect(uint64_t conn);
