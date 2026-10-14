// SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
/*
 * The static TC program (Spike A). `avulse_tc` parses the headers the way `avulse_proto::Packet`
 * does, writes the result to the per-CPU facts, and tail-calls the matcher generated from the
 * filter (slot SLOT_MATCHER). The matcher writes its verdict to the facts and tail-calls
 * `avulse_act` (slot SLOT_ACTION). A tail call does not return, so the action is a program of its
 * own. Without a matcher, the packet passes (fail-open).
 *
 * Headers are read with bpf_skb_load_bytes, which also reads paged (non-linear) data. The
 * programs are in "classifier" sections, the name aya knows for cls_bpf programs.
 */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#include "helpers.h"
#include "facts.h"

#define ETH_LEN 14
#define MAX_VLANS 2
#define MAX_IPV6_EXT 8

char LICENSE[] SEC("license") = "Dual LGPL/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct avulse_facts);
} avulse_facts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, SLOTS);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} avulse_progs SEC(".maps");

static __always_inline int ld8(struct __sk_buff *skb, __u32 off, __u32 *v)
{
    __u8 b;

    if (bpf_skb_load_bytes(skb, off, &b, 1))
        return -1;
    *v = b;
    return 0;
}

static __always_inline int ld16(struct __sk_buff *skb, __u32 off, __u32 *v)
{
    __u8 b[2];

    if (bpf_skb_load_bytes(skb, off, b, 2))
        return -1;
    *v = (__u32)b[0] << 8 | b[1];
    return 0;
}

static __always_inline int is_vlan(__u32 et)
{
    return et == 0x8100 || et == 0x88a8 || et == 0x9100;
}

/* Packet::parse_transport: the header must fit in [off, end). */
static __always_inline void parse_transport(struct __sk_buff *skb, struct avulse_facts *f,
                                            __u32 proto, __u32 off, __u32 end)
{
    __u32 seg = end - off, hl, v;

    switch (proto) {
    case 6: /* TCP */
        if (seg < 13 || ld8(skb, off + 12, &v))
            return;
        hl = (v >> 4) * 4;
        if (hl < 20 || hl > seg)
            return;
        f->flags |= F_TCP;
        break;
    case 17: /* UDP */
        if (seg < 8 || ld16(skb, off + 4, &v))
            return;
        if (v >= 8 && v <= seg)
            end = off + v;
        hl = 8;
        f->flags |= F_UDP;
        break;
    case 1: /* ICMP */
        if (seg < 8)
            return;
        hl = 8;
        f->flags |= F_ICMP;
        break;
    case 58: /* ICMPv6 */
        if (seg < 4)
            return;
        hl = seg < 8 ? seg : 8;
        f->flags |= F_ICMPV6;
        break;
    default:
        return;
    }
    f->l4 = off;
    f->l4_len = hl;
    f->pay = off + hl;
    f->pay_end = end;
}

static __always_inline void parse_ipv4(struct __sk_buff *skb, struct avulse_facts *f, __u32 off)
{
    __u32 len = f->len, v, hl, total, end, proto, frag;

    if (ld8(skb, off, &v))
        return;
    hl = (v & 0xf) * 4;
    if (v >> 4 != 4 || hl < 20 || off + hl > len)
        return;
    if (ld16(skb, off + 2, &total) || ld8(skb, off + 9, &proto) || ld16(skb, off + 6, &frag))
        return;
    /* Trim Ethernet padding; keep the whole buffer when the length is bogus or 0 (GSO). */
    end = total >= hl && off + total <= len ? off + total : len;
    f->flags |= F_IPV4;
    f->l3 = off;
    f->l3_len = hl;
    f->proto = proto;
    if (frag & 0x3fff)
        f->flags |= F_FRAG | (frag & 0x2000 ? F_MORE : 0);
    f->pay = off + hl;
    f->pay_end = end;
    if (!(frag & 0x1fff))
        parse_transport(skb, f, proto, off + hl, end);
}

static __always_inline void parse_ipv6(struct __sk_buff *skb, struct avulse_facts *f, __u32 off)
{
    __u32 len = f->len, v, plen, end, nh, cur, n, h, frag_off = 0;

    if (ld8(skb, off, &v) || v >> 4 != 6 || off + 40 > len)
        return;
    if (ld16(skb, off + 4, &plen) || ld8(skb, off + 6, &nh))
        return;
    end = off + 40 + plen;
    if (plen == 0 || end > len)
        end = len;
    f->flags |= F_IPV6;
    f->l3 = off;
    cur = off + 40;
#pragma unroll
    for (int i = 0; i < MAX_IPV6_EXT; i++) {
        if (nh == 0 || nh == 43 || nh == 60 || nh == 51) {
            if (cur + 2 > end || ld8(skb, cur + 1, &h))
                break;
            n = nh == 51 ? (h + 2) * 4 : (h + 1) * 8;
        } else if (nh == 44) {
            if (cur + 8 > end || ld16(skb, cur + 2, &h))
                break;
            frag_off = h >> 3;
            f->flags = (f->flags & ~F_MORE) | F_FRAG | (h & 1 ? F_MORE : 0);
            n = 8;
        } else {
            break;
        }
        if (cur + n > end || ld8(skb, cur, &nh))
            break;
        cur += n;
    }
    f->proto = nh;
    f->pay = cur;
    f->pay_end = end;
    if (!(f->flags & F_FRAG) || frag_off == 0)
        parse_transport(skb, f, nh, cur, end);
}

static __always_inline void parse_arp(struct __sk_buff *skb, struct avulse_facts *f, __u32 off)
{
    __u32 h, p, n;

    if (ld8(skb, off + 4, &h) || ld8(skb, off + 5, &p))
        return;
    n = 8 + 2 * (h + p);
    if (off + n > f->len)
        return;
    f->flags |= F_ARP;
    f->l3 = off;
    f->pay = f->pay_end = off + n;
}

/* Packet::parse for Link::Ethernet. */
static __always_inline void parse(struct __sk_buff *skb, struct avulse_facts *f)
{
    __u32 len = skb->len, off = ETH_LEN, et;

    __builtin_memset(f, 0, sizeof(*f));
    f->len = len;
    f->pay = f->pay_end = len;
    if (len < ETH_LEN || ld16(skb, 12, &et))
        return;
    f->flags = F_ETH;
    f->pay = off;
#pragma unroll
    for (int i = 0; i < MAX_VLANS; i++) {
        if (!is_vlan(et))
            break;
        if (off + 4 > len || ld16(skb, off + 2, &et))
            return;
        off += 4;
        f->pay = off;
    }
    if (is_vlan(et))
        return;
    if (et == 0x0806)
        parse_arp(skb, f, off);
    else if (et == 0x0800)
        parse_ipv4(skb, f, off);
    else if (et == 0x86dd)
        parse_ipv6(skb, f, off);
}

SEC("classifier")
int avulse_tc(struct __sk_buff *skb)
{
    __u32 zero = 0;
    struct avulse_facts *f = bpf_map_lookup_elem(&avulse_facts, &zero);

    if (!f)
        return TC_ACT_OK;
    parse(skb, f);
    bpf_tail_call(skb, &avulse_progs, SLOT_MATCHER);
    return TC_ACT_OK;
}

/* The action, after the matcher. For the spike: drop what matches, leave the rest to the next
 * classifier. Phase 2 diverts instead. */
SEC("classifier")
int avulse_act(struct __sk_buff *skb)
{
    __u32 zero = 0;
    struct avulse_facts *f = bpf_map_lookup_elem(&avulse_facts, &zero);

    if (!f)
        return TC_ACT_OK;
    return f->verdict ? TC_ACT_SHOT : TC_ACT_UNSPEC;
}
