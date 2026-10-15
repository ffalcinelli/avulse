// SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
/*
 * The static TC programs of a handle. `avulse_ingress` and `avulse_egress` run on the clsact
 * hooks of each interface. They check the handle's configuration (shutdown, heartbeat, marks,
 * layer), parse the headers the way `avulse_proto::Packet` does into the per-CPU facts, and
 * tail-call the matcher generated from the filter (slot SLOT_MATCHER). The matcher writes its
 * verdict to the facts and tail-calls `avulse_act` (slot SLOT_ACTION), which diverts, copies or
 * drops the packet. A tail call does not return, so the action is a program of its own.
 *
 * Everything fails open: without a configuration, a matcher or room in the ring, or once the
 * owner's heartbeat is stale, packets pass (TC_ACT_UNSPEC, so the next classifier runs).
 *
 * Headers are read with bpf_skb_load_bytes, which also reads paged (non-linear) data. The
 * programs are in "classifier" sections, the name aya knows for cls_bpf programs.
 */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#include "helpers.h"
#include "facts.h"
#include "abi.h"

#define ETH_LEN 14
#define MAX_VLANS 2
#define MAX_IPV6_EXT 8

/* The code is LGPL-3.0-or-later OR GPL-2.0-or-later; the kernel knows only its own list of
 * license strings, and the GPL-only helpers (bpf_fib_lookup) need one it counts as GPL. */
char LICENSE[] SEC("license") = "GPL";

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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct avulse_config);
} avulse_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STATS);
    __type(key, __u32);
    __type(value, __u64);
} avulse_stats SEC(".maps");

/* The loader sets the size (`Classifier::load`). */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} avulse_ring SEC(".maps");

static __always_inline void count(__u32 key)
{
    __u64 *v = bpf_map_lookup_elem(&avulse_stats, &key);

    if (v)
        *v += 1;
}

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

/* Is an ingress packet about to be forwarded, rather than delivered to this host? */
static __always_inline int forwarded(struct __sk_buff *skb, struct avulse_facts *f)
{
    struct bpf_fib_lookup p = {};
    __u16 ports[2];
    long r;

    p.ifindex = skb->ifindex;
    p.l4_protocol = f->proto;
    p.tot_len = f->pay_end - f->l3;
    if ((f->flags & (F_TCP | F_UDP)) && !bpf_skb_load_bytes(skb, f->l4, ports, 4)) {
        p.sport = ports[0];
        p.dport = ports[1];
    }
    if (f->flags & F_IPV4) {
        p.family = 2; /* AF_INET */
        if (bpf_skb_load_bytes(skb, f->l3 + 12, &p.ipv4_src, 4) ||
            bpf_skb_load_bytes(skb, f->l3 + 16, &p.ipv4_dst, 4))
            return 0;
    } else {
        p.family = 10; /* AF_INET6 */
        if (bpf_skb_load_bytes(skb, f->l3 + 8, p.ipv6_src, 16) ||
            bpf_skb_load_bytes(skb, f->l3 + 24, p.ipv6_dst, 16))
            return 0;
    }
    r = bpf_fib_lookup(skb, &p, sizeof(p), 0);
    return r == BPF_FIB_LKUP_RET_SUCCESS || r == BPF_FIB_LKUP_RET_NO_NEIGH ||
           r == BPF_FIB_LKUP_RET_FRAG_NEEDED;
}

/* Everything before the matcher: is the packet for this handle, and what are its facts. */
static __always_inline int classify(struct __sk_buff *skb, int outbound)
{
    __u32 zero = 0, mark = skb->mark, meta = outbound ? M_OUTBOUND : 0, vlan_tci = 0, layer;
    struct avulse_config *cfg = bpf_map_lookup_elem(&avulse_config, &zero);
    struct avulse_facts *f = bpf_map_lookup_elem(&avulse_facts, &zero);
    int network;
    __u64 timeout;

    if (!cfg || !f || (cfg->flags & CFG_SHUTDOWN))
        return TC_ACT_UNSPEC;
    timeout = cfg->heartbeat_timeout_ns;
    if (timeout && bpf_ktime_get_ns() - cfg->heartbeat_ns > timeout) {
        count(S_OWNER_GONE);
        return TC_ACT_UNSPEC;
    }
    if ((mark & MARK_MASK) == MARK_REDIRECT)
        return TC_ACT_UNSPEC;
    if ((mark & MARK_MASK) == MARK_INJECTED) {
        if (cfg->priority <= (mark & 0xffff))
            return TC_ACT_UNSPEC;
        meta |= M_IMPOSTOR;
        count(S_IMPOSTOR);
    }
    /* Loopback packets cross lo twice, egress then ingress: like WinDivert, report them once,
     * as outbound. */
    if (skb->ifindex == cfg->lo_ifindex) {
        if (!outbound || (cfg->flags & CFG_SKIP_LO))
            return TC_ACT_UNSPEC;
        meta |= M_LOOPBACK;
    }
    layer = cfg->layer;
    network = layer == LAYER_NETWORK || layer == LAYER_FORWARD;
    if (network) {
        /* A forwarded packet leaves through egress with the ingress device set. */
        int fwd = outbound && !(meta & M_LOOPBACK) && skb->ingress_ifindex != 0;

        if (fwd != (layer == LAYER_FORWARD))
            return TC_ACT_UNSPEC;
        if (fwd)
            meta |= M_FORWARD;
    }
    if (skb->vlan_present) {
        meta |= M_VLAN;
        vlan_tci = skb->vlan_tci;
    }

    parse(skb, f);
    f->layer = layer;
    f->ifindex = skb->ifindex;
    f->vlan_tci = vlan_tci;
    f->meta = meta;
    if (network) {
        /* The NETWORK layers see IP packets, from the IP header on. */
        if (!(f->flags & (F_IPV4 | F_IPV6)))
            return TC_ACT_UNSPEC;
        f->flags &= ~F_ETH;
        f->base = f->l3;
        if ((f->flags & F_FRAG) && !outbound && !(cfg->flags & CFG_FRAGMENTS))
            return TC_ACT_UNSPEC;
        if (!outbound && layer == LAYER_NETWORK && (cfg->flags & CFG_FWD_CHECK) &&
            forwarded(skb, f))
            return TC_ACT_UNSPEC;
    }
    bpf_tail_call(skb, &avulse_progs, SLOT_MATCHER);
    count(S_NO_MATCHER);
    return TC_ACT_UNSPEC;
}

SEC("classifier")
int avulse_ingress(struct __sk_buff *skb)
{
    return classify(skb, 0);
}

SEC("classifier")
int avulse_egress(struct __sk_buff *skb)
{
    return classify(skb, 1);
}

/*
 * Copies the first `len` bytes of the packet to the ring. bpf_ringbuf_reserve needs a constant
 * size, so records come in three size classes.
 */
#define EMIT(SIZE)                                                                            \
    do {                                                                                      \
        struct avulse_record *r =                                                             \
            bpf_ringbuf_reserve(&avulse_ring, sizeof(struct avulse_record) + (SIZE), 0);      \
        __u64 n = len;                                                                        \
                                                                                              \
        if (!r) {                                                                             \
            count(S_RING_FULL);                                                               \
            return -1;                                                                        \
        }                                                                                     \
        /* len is in [1, SIZE]; prove it with instructions no compiler rewrites and every     \
         * verifier tracks: n = ((len - 1) & (SIZE - 1)) + 1. */                              \
        asm volatile("%[n] += -1\n\t%[n] &= %[m]\n\t%[n] += 1" : [n] "+r"(n)                  \
                     : [m] "i"((SIZE) - 1));                                                  \
        if (bpf_skb_load_bytes(skb, 0, (void *)(r + 1), n)) {                                 \
            bpf_ringbuf_discard(r, 0);                                                        \
            count(S_LOAD_ERR);                                                                \
            return -1;                                                                        \
        }                                                                                     \
        r->timestamp = bpf_ktime_get_ns();                                                    \
        r->len = s->len;                                                                      \
        r->cap_len = n;                                                                       \
        r->ifindex = f->ifindex;                                                              \
        r->ingress_ifindex = s->ingress_ifindex;                                              \
        r->gso_size = s->gso_size;                                                            \
        r->gso_segs = s->gso_segs;                                                            \
        r->vlan_tci = f->vlan_tci;                                                            \
        r->l3 = f->l3;                                                                        \
        r->meta = f->meta | (sniffed ? M_SNIFFED : 0);                                        \
        r->layer = f->layer;                                                                  \
        r->flags = f->flags;                                                                  \
        r->reserved = 0;                                                                      \
        bpf_ringbuf_submit(r, 0);                                                             \
        return 0;                                                                             \
    } while (0)

/* The __sk_buff fields a record needs, read up front: the verifier allows context loads at
 * constant offsets only. */
struct skb_fields {
    __u32 len;
    __u32 ingress_ifindex;
    __u32 gso_size;
    __u32 gso_segs;
};

static __always_inline int emit(struct __sk_buff *skb, struct avulse_facts *f, __u32 len,
                                int sniffed)
{
    struct skb_fields fields, *s = &fields;

    fields.len = skb->len;
    fields.ingress_ifindex = skb->ingress_ifindex;
    fields.gso_size = skb->gso_size;
    fields.gso_segs = skb->gso_segs;
    barrier_var(s);
    if (len <= 2048)
        EMIT(2048);
    else if (len <= 16384)
        EMIT(16384);
    else
        EMIT(MAX_RECORD_DATA);
}

/* After the matcher: divert, copy or drop what matched. */
SEC("classifier")
int avulse_act(struct __sk_buff *skb)
{
    __u32 zero = 0, len = skb->len;
    struct avulse_config *cfg = bpf_map_lookup_elem(&avulse_config, &zero);
    struct avulse_facts *f = bpf_map_lookup_elem(&avulse_facts, &zero);
    int sniff;

    if (!cfg || !f || !f->verdict)
        return TC_ACT_UNSPEC;
    if (cfg->flags & CFG_DROP) {
        count(S_DROPPED);
        return TC_ACT_SHOT;
    }
    sniff = !!(cfg->flags & CFG_SNIFF);
    if (len > MAX_RECORD_DATA) {
        /* A diverted packet must be copied whole, or it cannot be sent back. */
        if (!sniff) {
            count(S_TOO_BIG);
            return TC_ACT_UNSPEC;
        }
        len = MAX_RECORD_DATA;
    }
    if (sniff && cfg->snaplen && len > cfg->snaplen)
        len = cfg->snaplen;
    if (len == 0 || emit(skb, f, len, sniff))
        return TC_ACT_UNSPEC;
    if (sniff) {
        count(S_SNIFFED);
        return TC_ACT_UNSPEC;
    }
    count(S_DIVERTED);
    return TC_ACT_STOLEN;
}
