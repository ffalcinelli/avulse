/* The Rust static library (src/lib.rs) as the Swift code sees it. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

int32_t avulse_spike_matches(const uint8_t *prog, size_t prog_len, const uint8_t *pkt,
                             size_t pkt_len, uint32_t link, bool outbound);
ssize_t avulse_spike_compile(const uint8_t *src, size_t src_len, uint8_t *out, size_t cap);
