# C

`libavulse` is the C interface of the handle API: the `avulse-capi` crate, built as a shared
(`libavulse.so`) and a static (`libavulse.a`) library, with the header
[`crates/capi/include/avulse.h`](https://github.com/ffalcinelli/avulse/blob/main/crates/capi/include/avulse.h).
It is version 0.x: the interface may still change.

```console
$ cargo build --release -p avulse-capi
$ cc -I crates/capi/include app.c -L target/release -lavulse
```

## Conventions

- Every call returns `AVULSE_OK` (0) or a negative status: `AVULSE_E_FILTER`, `AVULSE_E_INVALID`,
  `AVULSE_E_UNSUPPORTED`, `AVULSE_E_SHUTDOWN`, `AVULSE_E_TIMEOUT`, `AVULSE_E_BUFFER` or
  `AVULSE_E_IO`.
- After a failed call, `avulse_last_error()` describes what went wrong. For a filter, it shows
  where the error is, as `avulse filter check` does. `avulse_last_os_error()` gives the system's
  error number behind `AVULSE_E_IO`. Both are per thread.
- The layers, events, flags, parameters and shutdown directions have WinDivert's numbers, as
  `AVULSE_*` constants.
- `struct avulse_address` has the layout of the Rust `Address`, version 3 (216 bytes); the
  header checks the layout with static asserts. Start new addresses with `avulse_address_init`.
- A handle can be used from several threads at once, except with `avulse_close`.

## An example

```c
#include <stdio.h>
#include "avulse.h"

int main(void)
{
    avulse_handle *h;
    unsigned char buf[AVULSE_MAX_PACKET_LEN];
    struct avulse_address addr;
    size_t len;

    /* Divert outbound DNS queries, print them, and send them on. */
    if (avulse_open("outbound and udp.dstport == 53", AVULSE_LAYER_NETWORK, 0, 0, &h)) {
        fprintf(stderr, "%s\n", avulse_last_error());
        return 1;
    }
    while (avulse_recv(h, buf, sizeof(buf), &len, &addr, -1) == AVULSE_OK) {
        printf("%zu bytes on interface %u\n", len, addr.if_idx);
        avulse_send(h, buf, len, &addr);
    }
    avulse_close(h);
    return 0;
}
```

## Calls

| Call | What it does |
| --- | --- |
| `avulse_open`, `avulse_open_ex` | Open a handle (with `struct avulse_open_options`: priority, flags, WinDivert syntax, interfaces) |
| `avulse_recv` | Wait for a packet or event, with a timeout in milliseconds (negative: forever; 0: only what is there) |
| `avulse_recv_batch` | Wait for one, then take those already there, back to back in the buffer |
| `avulse_send`, `avulse_send_batch` | Send packets |
| `avulse_shutdown`, `avulse_close` | Stop receiving or sending; close and free the handle |
| `avulse_set_param`, `avulse_get_param` | The queue parameters |
| `avulse_fd` | A descriptor readable when `avulse_recv` would not block, for `poll` and `epoll` |
| `avulse_stats` | The handle's counters: diverted, sniffed, dropped, and what was passed on or lost, and why |
| `avulse_cleanup` | Remove what dead processes left behind |
| `avulse_filter_check`, `avulse_filter_format`, `avulse_filter_convert`, `avulse_filter_eval` | The filter language without a handle: check, format, convert a WinDivert filter, evaluate on a packet |

The [Rust crate's documentation](handles.md) describes what the calls do on each platform; the
C calls are thin wrappers around it.
