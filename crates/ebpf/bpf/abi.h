/* SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later */
/*
 * What the capture programs share with user space (`crates/ebpf/src/abi.rs`): the handle's
 * configuration, the ring buffer records, the statistics and the packet marks.
 */
#ifndef AVULSE_ABI_H
#define AVULSE_ABI_H

#include <linux/types.h>

/* Layers (`avulse_filter::Layer`) the TC programs serve. */
#define LAYER_NETWORK 0
#define LAYER_FORWARD 1
#define LAYER_ETHERNET 5

/* avulse_config.flags */
#define CFG_SNIFF     (1u << 0) /* copy matching packets to the ring; they go on */
#define CFG_DROP      (1u << 1) /* drop matching packets; copy nothing */
#define CFG_FRAGMENTS (1u << 2) /* also take inbound IP fragments */
#define CFG_SHUTDOWN  (1u << 3) /* pass everything (shutdown of the receive side) */
#define CFG_FWD_CHECK (1u << 4) /* IP forwarding is on: ingress at NETWORK skips forwarded */
#define CFG_SKIP_LO   (1u << 5) /* lo is attached for injection only */

/* The handle's configuration: the one entry of the `avulse_config` array. User space writes
 * it whole; the heartbeat refreshes `heartbeat_ns`. */
struct avulse_config {
    __u64 heartbeat_ns;         /* bpf_ktime_get_ns() of the last refresh */
    __u64 heartbeat_timeout_ns; /* pass everything once the heartbeat is older; 0: no check */
    __u32 flags;                /* CFG_* */
    __u32 priority;             /* TC priority (lower runs first) */
    __u32 lo_ifindex;           /* the loopback device */
    __u32 snaplen;              /* SNIFF copies at most this much; 0: everything */
    __u8 layer;                 /* LAYER_* */
    __u8 pad[7];
};

_Static_assert(sizeof(struct avulse_config) == 40, "abi.rs");

/* The largest packet a record holds: a GSO or GRO packet of up to 64 KiB. */
#define MAX_RECORD_DATA 65536

/* A ring buffer record: this header, then `cap_len` bytes of the packet from its first byte
 * (the link-layer header included, `l3` bytes of it). */
struct avulse_record {
    __u64 timestamp;       /* bpf_ktime_get_ns() */
    __u32 len;             /* skb->len */
    __u32 cap_len;         /* bytes that follow */
    __u32 ifindex;         /* the device it was seen on */
    __u32 ingress_ifindex; /* skb->ingress_ifindex (0: locally generated) */
    __u16 gso_size;        /* skb->gso_size, 0 if not GSO */
    __u16 gso_segs;
    __u16 vlan_tci;        /* the offloaded outer VLAN tag, when M_VLAN */
    __u16 l3;              /* offset of the IP or ARP header (the link-layer header length) */
    __u8 meta;             /* M_* (facts.h) */
    __u8 layer;
    __u16 flags;           /* the F_* presence bits of the facts (low 16) */
    __u32 reserved;
};

_Static_assert(sizeof(struct avulse_record) == 40, "abi.rs");

/* Statistics: a per-CPU array of __u64. */
#define S_DIVERTED   0 /* stolen and copied to the ring */
#define S_SNIFFED    1 /* copied, and passed on */
#define S_DROPPED    2 /* dropped (CFG_DROP) */
#define S_RING_FULL  3 /* matched, but the ring was full: passed */
#define S_OWNER_GONE 4 /* stale heartbeat: passed */
#define S_TOO_BIG    5 /* matched, but too large to divert whole: passed */
#define S_LOAD_ERR   6 /* the copy to the ring failed: passed */
#define S_NO_MATCHER 7 /* empty matcher slot: passed */
#define S_IMPOSTOR   8 /* seen with the mark of a higher-priority handle */
#define STATS        9

/*
 * Packet marks (skb->mark). Avulse's prefixes differ from ebpfdivert's (0x4D49...), so that the
 * two never take each other's packets for their own.
 *  - MARK_INJECTED | tc_priority: an injected packet. Handles of the same or a higher priority
 *    (lower or equal TC priority) skip it; lower ones see an impostor.
 *  - MARK_REDIRECT | ifindex: an inbound packet sent through lo, for the lo ingress hook to
 *    redirect (Step 9). Every handle skips it.
 */
#define MARK_MASK     0xffff0000u
#define MARK_INJECTED 0x41560000u /* "AV" */
#define MARK_REDIRECT 0x41570000u

#endif
