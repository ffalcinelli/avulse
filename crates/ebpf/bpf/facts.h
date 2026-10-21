/* SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later */
/*
 * The facts the static TC program leaves for the generated matcher: one per CPU, in the
 * `avulse_facts` map. The offsets are part of the contract with the code generator
 * (`crates/ebpf/src/facts.rs`); the asserts below keep them in step.
 */
#ifndef AVULSE_FACTS_H
#define AVULSE_FACTS_H

#include <linux/types.h>

/* Presence bits of `flags`, as `avulse_proto::Packet` reports the headers. */
#define F_ETH    (1u << 0)
#define F_IPV4   (1u << 1)
#define F_IPV6   (1u << 2)
#define F_ARP    (1u << 3)
#define F_TCP    (1u << 4)
#define F_UDP    (1u << 5)
#define F_ICMP   (1u << 6)
#define F_ICMPV6 (1u << 7)
#define F_FRAG   (1u << 8) /* an IPv4 fragment, or an IPv6 fragment header */
#define F_MORE   (1u << 9) /* ... with more fragments to come */

/* Bits of `meta`, which the capture records repeat (`struct avulse_record`). */
#define M_OUTBOUND (1u << 0) /* egress */
#define M_LOOPBACK (1u << 1) /* on the loopback device */
#define M_IMPOSTOR (1u << 2) /* injected by a handle of lower or equal priority */
#define M_VLAN     (1u << 3) /* `vlan_tci` holds an offloaded outer VLAN tag */
#define M_FORWARD  (1u << 4) /* forwarded (NETWORK_FORWARD) */
#define M_SNIFFED  (1u << 5) /* records only: the packet went on */
#define M_VLAN_AD  (1u << 6) /* with M_VLAN: the offloaded tag's TPID is 0x88a8 (else 0x8100) */

/* Slots of the `avulse_progs` program array. */
#define SLOT_MATCHER 0
#define SLOT_ACTION  1
#define SLOT_OPTIONS 2
#define SLOTS        3

struct avulse_facts {
    __u32 len;      /* frame length (skb->len) */
    __u32 flags;    /* F_* */
    __u32 l3;       /* offset of the ARP or IP header */
    __u32 l4;       /* offset of the transport header */
    __u32 l4_len;   /* transport header length */
    __u32 pay;      /* payload start */
    __u32 pay_end;  /* payload end (IP and UDP lengths applied) */
    __u8 proto;     /* IPv4 protocol, or IPv6 next header after the extension headers */
    __u8 l3_len;    /* IPv4 header length */
    __u8 verdict;   /* written by the matcher: 1 if the filter matches */
    __u8 layer;     /* the handle's layer (WinDivert numbering; ETHERNET is 5) */
    __u32 base;     /* where what the filter sees starts: 0, or l3 at the NETWORK layers */
    __u32 ifindex;  /* the device the packet is on */
    __u16 vlan_tci; /* the offloaded outer VLAN tag, when M_VLAN */
    __u8 meta;      /* M_* */
    __u8 vlans;     /* VLAN tags in the frame (an offloaded one aside), at most 2 */
    __u8 opts[4];   /* first MSS, WS, SACK_PERM and TS options, from the TCP header; 0: none */
};

_Static_assert(__builtin_offsetof(struct avulse_facts, len) == 0, "facts.rs");
_Static_assert(__builtin_offsetof(struct avulse_facts, flags) == 4, "facts.rs");
_Static_assert(__builtin_offsetof(struct avulse_facts, l3) == 8, "facts.rs");
_Static_assert(__builtin_offsetof(struct avulse_facts, l4) == 12, "facts.rs");
_Static_assert(__builtin_offsetof(struct avulse_facts, l4_len) == 16, "facts.rs");
_Static_assert(__builtin_offsetof(struct avulse_facts, pay) == 20, "facts.rs");
_Static_assert(__builtin_offsetof(struct avulse_facts, pay_end) == 24, "facts.rs");
_Static_assert(__builtin_offsetof(struct avulse_facts, proto) == 28, "facts.rs");
_Static_assert(__builtin_offsetof(struct avulse_facts, l3_len) == 29, "facts.rs");
_Static_assert(__builtin_offsetof(struct avulse_facts, verdict) == 30, "facts.rs");
_Static_assert(__builtin_offsetof(struct avulse_facts, layer) == 31, "facts.rs");
_Static_assert(__builtin_offsetof(struct avulse_facts, base) == 32, "facts.rs");
_Static_assert(__builtin_offsetof(struct avulse_facts, ifindex) == 36, "facts.rs");
_Static_assert(__builtin_offsetof(struct avulse_facts, vlan_tci) == 40, "facts.rs");
_Static_assert(__builtin_offsetof(struct avulse_facts, meta) == 42, "facts.rs");
_Static_assert(__builtin_offsetof(struct avulse_facts, vlans) == 43, "facts.rs");
_Static_assert(__builtin_offsetof(struct avulse_facts, opts) == 44, "facts.rs");
_Static_assert(sizeof(struct avulse_facts) == 48, "facts.rs");

#endif
