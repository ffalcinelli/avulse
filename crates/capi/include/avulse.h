/* SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later */
/*
 * libavulse: divert, modify and re-inject network packets.
 *
 * The C interface of the `avulse` Rust crate (https://ffalcinelli.github.io/avulse/). A handle
 * is opened at a layer with a filter (Wireshark display-filter syntax, or WinDivert's), a
 * priority and flags; it receives the packets or events the filter matches, each with an
 * address, and at the packet layers it sends packets.
 *
 * Every call returns AVULSE_OK (0) or a negative AVULSE_E_* status. After an error,
 * avulse_last_error() describes it (for a filter, with where it is wrong), and
 * avulse_last_os_error() gives the system's error number of AVULSE_E_IO; both are per thread.
 * Handles may be used from several threads at once, except avulse_close.
 *
 * The structures below have the layout of the Rust types, which the asserts at the end of this
 * file pin. Version 0.x: the interface may still change.
 */
#ifndef AVULSE_H
#define AVULSE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The layout version of struct avulse_address. */
#define AVULSE_ADDRESS_VERSION 3
/* A buffer of this many bytes holds any packet. */
#define AVULSE_MAX_PACKET_LEN 65600

/* Statuses. */
#define AVULSE_OK 0
#define AVULSE_E_FILTER (-1)      /* the filter does not compile */
#define AVULSE_E_INVALID (-2)     /* an argument is out of range or does not apply */
#define AVULSE_E_UNSUPPORTED (-3) /* this platform's backend cannot do it */
#define AVULSE_E_SHUTDOWN (-4)    /* the handle was shut down in this direction */
#define AVULSE_E_TIMEOUT (-5)     /* nothing arrived in time */
#define AVULSE_E_BUFFER (-6)      /* the packet does not fit the buffer; it is dropped */
#define AVULSE_E_IO (-7)          /* the system refused: see avulse_last_os_error() */

/* Layers (WinDivert's numbers, and ETHERNET). */
#define AVULSE_LAYER_NETWORK 0
#define AVULSE_LAYER_NETWORK_FORWARD 1
#define AVULSE_LAYER_FLOW 2
#define AVULSE_LAYER_SOCKET 3
#define AVULSE_LAYER_REFLECT 4
#define AVULSE_LAYER_ETHERNET 5

/* Events (WinDivert's numbers). */
#define AVULSE_EVENT_PACKET 0
#define AVULSE_EVENT_FLOW_ESTABLISHED 1
#define AVULSE_EVENT_FLOW_DELETED 2
#define AVULSE_EVENT_SOCKET_BIND 3
#define AVULSE_EVENT_SOCKET_CONNECT 4
#define AVULSE_EVENT_SOCKET_LISTEN 5
#define AVULSE_EVENT_SOCKET_ACCEPT 6
#define AVULSE_EVENT_SOCKET_CLOSE 7
#define AVULSE_EVENT_REFLECT_OPEN 8
#define AVULSE_EVENT_REFLECT_CLOSE 9

/* Flags (WinDivert's values). */
#define AVULSE_FLAG_SNIFF 0x0001
#define AVULSE_FLAG_DROP 0x0002
#define AVULSE_FLAG_RECV_ONLY 0x0004
#define AVULSE_FLAG_SEND_ONLY 0x0008
#define AVULSE_FLAG_NO_INSTALL 0x0010
#define AVULSE_FLAG_FRAGMENTS 0x0020

/* Priorities. */
#define AVULSE_PRIORITY_HIGHEST 30000
#define AVULSE_PRIORITY_LOWEST (-30000)

/* Queue parameters. */
#define AVULSE_PARAM_QUEUE_LENGTH 0 /* packets: 32 to 16384, default 4096 */
#define AVULSE_PARAM_QUEUE_TIME 1   /* milliseconds: 100 to 16000, default 2000 */
#define AVULSE_PARAM_QUEUE_SIZE 2   /* bytes: 65535 to 33554432, default 4194304 */

/* What avulse_shutdown stops (WinDivert's values). */
#define AVULSE_SHUTDOWN_RECV 1
#define AVULSE_SHUTDOWN_SEND 2
#define AVULSE_SHUTDOWN_BOTH 3

/* Filter languages. */
#define AVULSE_SYNTAX_NATIVE 0
#define AVULSE_SYNTAX_WINDIVERT 1

/* The flow or socket of a FLOW or SOCKET event. */
struct avulse_flow {
    uint64_t endpoint_id;
    uint64_t parent_endpoint_id;
    uint32_t process_id;
    uint16_t local_port;
    uint16_t remote_port;
    uint8_t local_addr[16];  /* network byte order, IPv4 as ::ffff:a.b.c.d */
    uint8_t remote_addr[16];
    uint8_t protocol;
    uint8_t reserved[7];
    char process_name[32];   /* UTF-8, NUL-padded (not terminated when 32 bytes long) */
};

/* The handle a REFLECT event is about. */
struct avulse_reflect {
    int64_t timestamp; /* when it was opened */
    uint64_t flags;
    uint32_t process_id;
    int16_t priority;
    uint8_t layer;
    uint8_t syntax;    /* AVULSE_SYNTAX_* of its filter, the event's data */
};

/*
 * What a handle knows about a packet or event. To send a received packet back, pass the
 * address it came with; for a new one, start from avulse_address_init().
 */
struct avulse_address {
    int64_t timestamp;     /* nanoseconds of the monotonic clock */
    uint16_t version;      /* AVULSE_ADDRESS_VERSION */
    uint8_t layer;         /* AVULSE_LAYER_* */
    uint8_t event;         /* AVULSE_EVENT_* */
    bool outbound;
    bool loopback;
    bool impostor;
    bool sniffed;
    bool ipv6;
    bool ip_checksum;      /* valid; when sending, false asks for it to be computed */
    bool tcp_checksum;
    bool udp_checksum;
    uint32_t if_idx;
    uint32_t sub_if_idx;
    uint16_t vlan_tci;
    bool vlan;
    uint8_t reserved;
    struct avulse_flow flow;       /* FLOW, SOCKET */
    struct avulse_reflect reflect; /* REFLECT */
    uint8_t context[64];           /* opaque: what the backend needs to reinject the packet */
};

/* Options of avulse_open_ex; set `size` to sizeof(struct avulse_open_options). */
struct avulse_open_options {
    uint32_t size;
    int16_t priority;
    uint8_t syntax;                 /* AVULSE_SYNTAX_* */
    uint64_t flags;                 /* AVULSE_FLAG_* */
    const char *const *interfaces;  /* capture only on these interfaces; NULL: all */
    size_t interface_count;
};

/* A handle's counters (avulse_stats): what happened to what its filter matched. */
struct avulse_stats {
    uint64_t diverted;    /* diverted to the handle */
    uint64_t sniffed;     /* copied to it and passed on */
    uint64_t dropped;     /* dropped */
    uint64_t ring_full;   /* passed on: the kernel's buffer to the handle was full */
    uint64_t owner_gone;  /* passed on: the owner stopped answering */
    uint64_t too_big;     /* passed on: too large to divert whole */
    uint64_t load_errors; /* passed on: the kernel could not copy them */
    uint64_t queue_drops; /* lost in user space: the queue was full or they waited too long */
};

typedef struct avulse_handle avulse_handle;

/* The library's version, such as "0.1.0". */
const char *avulse_version(void);

/* What the last failed call on this thread said; empty if none. Valid until the next call. */
const char *avulse_last_error(void);
/* The system's error number behind the last AVULSE_E_IO on this thread. */
int avulse_last_os_error(void);

/* Opens a handle with a native filter. */
int avulse_open(const char *filter, uint8_t layer, int16_t priority, uint64_t flags,
                avulse_handle **handle);
/* Opens a handle with options. */
int avulse_open_ex(const char *filter, uint8_t layer, const struct avulse_open_options *options,
                   avulse_handle **handle);

/*
 * Waits for a packet or event, at most `timeout_ms` (forever if negative; 0 takes only what is
 * there), copies it to `buf` and sets `*len` and `*addr`. With AVULSE_E_BUFFER, `*len` is the
 * length that was needed.
 */
int avulse_recv(avulse_handle *handle, void *buf, size_t buf_len, size_t *len,
                struct avulse_address *addr, int64_t timeout_ms);
/*
 * Waits for the first packet as avulse_recv does, then takes those already there, up to `n`,
 * back to back in `buf`: packet i has length lens[i] and address addrs[i]. Sets `*count`.
 */
int avulse_recv_batch(avulse_handle *handle, void *buf, size_t buf_len,
                      struct avulse_address *addrs, size_t *lens, size_t n, size_t *count,
                      int64_t timeout_ms);
/* Sends a packet: from the IP header, or from the Ethernet header at the ETHERNET layer. */
int avulse_send(avulse_handle *handle, const void *packet, size_t len,
                const struct avulse_address *addr);
/*
 * Sends `n` packets in order. Sets `*sent` to how many were sent; fails only if the first one
 * does (the ones after a failure are not sent).
 */
int avulse_send_batch(avulse_handle *handle, const void *const *packets, const size_t *lens,
                      const struct avulse_address *addrs, size_t n, size_t *sent);
/* Stops receiving, sending, or both (AVULSE_SHUTDOWN_*). */
int avulse_shutdown(avulse_handle *handle, int how);
/* Sets or reads a queue parameter (AVULSE_PARAM_*). */
int avulse_set_param(avulse_handle *handle, int param, uint64_t value);
int avulse_get_param(const avulse_handle *handle, int param, uint64_t *value);
/* The handle's counters; AVULSE_E_UNSUPPORTED where the backend keeps none. */
int avulse_stats(const avulse_handle *handle, struct avulse_stats *stats);
/*
 * A file descriptor that is readable when avulse_recv would not block (for poll or epoll),
 * owned by the handle; -1 where the platform has none.
 */
int avulse_fd(const avulse_handle *handle);
/* Closes the handle and frees it; it must not be in use. NULL does nothing. */
int avulse_close(avulse_handle *handle);

/* An empty address at `layer`: inbound, no interface, every checksum to be computed. */
void avulse_address_init(struct avulse_address *addr, uint8_t layer);
/* Removes what dead processes left behind; sets `*count` to how many handles that was. */
int avulse_cleanup(size_t *count);

/* Whether a filter compiles (AVULSE_SYNTAX_*; the layer matters for WinDivert filters). */
int avulse_filter_check(const char *filter, int syntax, uint8_t layer);
/*
 * Writes the canonical form of a native filter, or the native equivalent of a WinDivert one
 * (avulse_filter_convert), as a NUL-terminated string. `*needed` is its size, NUL included;
 * when `out_len` is smaller, nothing is written and the status is AVULSE_E_BUFFER.
 */
int avulse_filter_format(const char *filter, char *out, size_t out_len, size_t *needed);
int avulse_filter_convert(const char *windivert, uint8_t layer, char *out, size_t out_len,
                          size_t *needed);
/*
 * Evaluates a native filter on a packet (from the Ethernet header if `ethernet`, else from the
 * IP header) with the metadata of `addr` (NULL: an empty NETWORK address). Returns 1 if it
 * matches, 0 if not, or a negative status.
 */
int avulse_filter_eval(const char *filter, const void *packet, size_t len, bool ethernet,
                       const struct avulse_address *addr);

#ifdef __cplusplus
}
#endif

#ifndef __cplusplus
_Static_assert(sizeof(struct avulse_flow) == 96, "avulse_flow");
_Static_assert(offsetof(struct avulse_flow, local_addr) == 24, "avulse_flow");
_Static_assert(offsetof(struct avulse_flow, protocol) == 56, "avulse_flow");
_Static_assert(offsetof(struct avulse_flow, process_name) == 64, "avulse_flow");
_Static_assert(sizeof(struct avulse_reflect) == 24, "avulse_reflect");
_Static_assert(offsetof(struct avulse_reflect, layer) == 22, "avulse_reflect");
_Static_assert(offsetof(struct avulse_reflect, syntax) == 23, "avulse_reflect");
_Static_assert(sizeof(struct avulse_address) == 216, "avulse_address");
_Static_assert(sizeof(struct avulse_stats) == 64, "avulse_stats");
_Static_assert(offsetof(struct avulse_address, version) == 8, "avulse_address");
_Static_assert(offsetof(struct avulse_address, outbound) == 12, "avulse_address");
_Static_assert(offsetof(struct avulse_address, if_idx) == 20, "avulse_address");
_Static_assert(offsetof(struct avulse_address, vlan) == 30, "avulse_address");
_Static_assert(offsetof(struct avulse_address, flow) == 32, "avulse_address");
_Static_assert(offsetof(struct avulse_address, reflect) == 128, "avulse_address");
_Static_assert(offsetof(struct avulse_address, context) == 152, "avulse_address");
#endif

#endif
