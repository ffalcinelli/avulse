// SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
/*
 * The event programs of a FLOW or SOCKET handle, attached to the cgroup v2 root through links
 * (they go away with the process that owns them). They report what sockets do as records in
 * the ring buffer (`struct avulse_event`, abi.h); user space builds the addresses and filters.
 *
 *   SOCKET: BIND (post_bind), CONNECT (connect), LISTEN and ACCEPT (sockops), CLOSE
 *           (sock_release).
 *   FLOW:   ESTABLISHED and DELETED: for TCP from sockops (established, then the state going
 *           to CLOSE); for UDP the first packet of each 5-tuple (cgroup_skb), and, when the
 *           socket goes away, one EV_RELEASED record that user space turns into DELETED for
 *           each of its flows.
 *
 * Every socket gets storage of its own when it is made (sock_create): the process's ID and
 * name, which later events (sockops, sock_release, packets) cannot ask the current task for,
 * and its endpoints, which sock_release cannot read.
 *
 * A SOCKET handle without SNIFF refuses the binds and connects its filter matches. The filter
 * runs in the kernel: bind and connect write the event's facts (struct avulse_ev_facts) and its
 * record to the per-CPU `avulse_ev_state`, and tail-call the matcher generated for their kind of
 * program (a program array holds programs of one type, so each of connect4, connect6,
 * post_bind4 and post_bind6 has its own array, matcher and action program). The matcher writes
 * its verdict and tail-calls the action, which reports the event, marked EV_BLOCKED when it
 * refuses it, and returns 0 (the call fails with EPERM) or 1.
 *
 * Like the TC programs, they fail open: without a configuration, once it is shut down, or once
 * the owner's heartbeat is stale, they report nothing and let every call through; without a
 * matcher, the call goes through and is reported.
 */
#include <linux/bpf.h>

#include "helpers.h"
#include "abi.h"
#include "facts.h"

#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define TCP_CLOSE 7

char LICENSE[] SEC("license") = "GPL";

/*
 * Whether cgroup socket programs may ask for the current task's PID and name. The loader sets
 * it before loading, and loads again with 0 when the kernel refuses the helpers.
 */
const volatile __u32 avulse_have_task = 1;

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

/* The loader sets the size (`Events::load_with_ring`). */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} avulse_ring SEC(".maps");

/* The event a matcher decides, and its record, which the action reports. */
struct ev_state {
    struct avulse_ev_facts f;
    struct avulse_event e;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ev_state);
} avulse_ev_state SEC(".maps");

/* The matcher (SLOT_MATCHER) and the action (SLOT_ACTION) of each kind of program. */
#define PROG_ARRAY(name)                                                                      \
    struct {                                                                                  \
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);                                                \
        __uint(max_entries, 2);                                                               \
        __uint(key_size, sizeof(__u32));                                                      \
        __uint(value_size, sizeof(__u32));                                                    \
    } name SEC(".maps")

PROG_ARRAY(avulse_progs_connect4);
PROG_ARRAY(avulse_progs_connect6);
PROG_ARRAY(avulse_progs_bind4);
PROG_ARRAY(avulse_progs_bind6);

/* What a socket's later events need to know. */
struct sock_info {
    __u32 pid;
    __u16 local_port;
    __u16 remote_port;
    __u8 family;
    __u8 flags; /* EV_OUTBOUND: the flow's direction, for its DELETED event */
    __u8 pad[2];
    __u8 local_addr[16];
    __u8 remote_addr[16];
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_CLONE);
    __type(key, int);
    __type(value, struct sock_info);
} avulse_sockets SEC(".maps");

/* The UDP 5-tuples already reported as established, by socket. */
struct udp_flow {
    __u64 endpoint;
    __u8 remote_addr[16];
    __u16 remote_port;
    __u16 local_port;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct udp_flow);
    __type(value, __u8);
} avulse_udp_flows SEC(".maps");

static __always_inline void count(__u32 key)
{
    __u64 *v = bpf_map_lookup_elem(&avulse_stats, &key);

    if (v)
        *v += 1;
}

/* The configuration, if the handle is alive and listening, at FLOW or SOCKET. */
static __always_inline struct avulse_config *live(void)
{
    __u32 zero = 0;
    struct avulse_config *cfg = bpf_map_lookup_elem(&avulse_config, &zero);
    __u64 timeout;

    if (!cfg || (cfg->flags & CFG_SHUTDOWN))
        return 0;
    timeout = cfg->heartbeat_timeout_ns;
    if (timeout && bpf_ktime_get_ns() - cfg->heartbeat_ns > timeout) {
        count(S_OWNER_GONE);
        return 0;
    }
    return cfg;
}

static __always_inline void v4_mapped(__u8 *dst, __u32 addr)
{
    __builtin_memset(dst, 0, 10);
    dst[10] = 0xff;
    dst[11] = 0xff;
    __builtin_memcpy(dst + 12, &addr, 4);
}

/*
 * Reads a 16-byte address from a context array. The verifier allows context loads at constant
 * offsets only: the barriers stop clang from computing the address once and indexing it.
 */
#define CTX_IP6(dst, ctx, field)                                                              \
    do {                                                                                      \
        __u32 w_[4];                                                                          \
        w_[0] = (ctx)->field[0];                                                              \
        barrier_var(ctx);                                                                     \
        w_[1] = (ctx)->field[1];                                                              \
        barrier_var(ctx);                                                                     \
        w_[2] = (ctx)->field[2];                                                              \
        barrier_var(ctx);                                                                     \
        w_[3] = (ctx)->field[3];                                                              \
        barrier_var(ctx);                                                                     \
        __builtin_memcpy((dst), w_, 16);                                                      \
    } while (0)

static __always_inline __u32 current_pid(void)
{
    if (avulse_have_task)
        return bpf_get_current_pid_tgid() >> 32;
    return 0;
}

static __always_inline void current_comm(char *comm)
{
    if (avulse_have_task)
        bpf_get_current_comm(comm, 16);
}

static __always_inline struct sock_info *info_of(void *sk, int create)
{
    if (!sk)
        return 0;
    return bpf_sk_storage_get(&avulse_sockets, sk, 0, create ? BPF_SK_STORAGE_GET_F_CREATE : 0);
}

/* The process the socket was made by, from its storage. */
static __always_inline void owner(struct avulse_event *e, struct sock_info *info)
{
    if (!info)
        return;
    e->pid = info->pid;
    __builtin_memcpy(e->comm, info->comm, 16);
}

/* Keeps the event's endpoints in the socket's storage, for its later events. */
static __always_inline void remember(struct sock_info *info, const struct avulse_event *e)
{
    if (!info)
        return;
    info->family = e->family;
    if (e->local_port)
        info->local_port = e->local_port;
    if (e->remote_port) {
        info->remote_port = e->remote_port;
        __builtin_memcpy(info->remote_addr, e->remote_addr, 16);
    }
    __builtin_memcpy(info->local_addr, e->local_addr, 16);
}

static __always_inline void submit(const struct avulse_event *e)
{
    struct avulse_event *out = bpf_ringbuf_reserve(&avulse_ring, sizeof(*out), 0);

    if (!out) {
        count(S_RING_FULL);
        return;
    }
    __builtin_memcpy(out, e, sizeof(*out));
    bpf_ringbuf_submit(out, 0);
}

static __always_inline int mapped(const __u8 *a)
{
    __u64 hi;
    __u16 mid;

    __builtin_memcpy(&hi, a, 8);
    __builtin_memcpy(&mid, a + 8, 2);
    return hi == 0 && mid == 0 && a[10] == 0xff && a[11] == 0xff;
}

/* As user space sees it: ::1, or an IPv4-mapped 127.0.0.0/8 address. */
static __always_inline int is_loopback(const __u8 *a)
{
    __u64 hi, lo;

    if (mapped(a))
        return a[12] == 127;
    __builtin_memcpy(&hi, a, 8);
    __builtin_memcpy(&lo, a + 8, 8);
    return hi == 0 && lo == __builtin_bswap64(1);
}

/* facts::ev::from_record. */
static __always_inline void fill_facts(struct avulse_ev_facts *f, const struct avulse_event *e)
{
    f->pid = e->pid;
    f->flags = (mapped(e->local_addr) ? EF_LOCAL4 : EF_LOCAL6) |
               (mapped(e->remote_addr) ? EF_REMOTE4 : EF_REMOTE6);
    f->local_port = e->local_port;
    f->remote_port = e->remote_port;
    __builtin_memcpy(f->local_addr, e->local_addr, 16);
    f->protocol = e->protocol;
    f->event = e->event;
    f->verdict = 0;
    f->meta = ((e->flags & EV_OUTBOUND) ? M_OUTBOUND : 0) |
              ((is_loopback(e->local_addr) || is_loopback(e->remote_addr)) ? M_LOOPBACK : 0);
    __builtin_memcpy(f->remote_addr, e->remote_addr, 16);
    f->endpoint = e->endpoint;
    __builtin_memcpy(f->comm, e->comm, 16);
}

/*
 * Reports `e`, or, for a handle that refuses calls, hands it to the matcher in `progs`, which
 * does not return. Returns what the call gets when there is no matcher: through.
 */
static __always_inline int decide(void *ctx, struct avulse_config *cfg, void *progs,
                                  const struct avulse_event *e)
{
    __u32 zero = 0;
    struct ev_state *s;

    if (!(cfg->flags & CFG_SNIFF) && (s = bpf_map_lookup_elem(&avulse_ev_state, &zero))) {
        fill_facts(&s->f, e);
        __builtin_memcpy(&s->e, e, sizeof(*e));
        bpf_tail_call(ctx, progs, SLOT_MATCHER);
        count(S_NO_MATCHER);
    }
    submit(e);
    return 1;
}

/* After the matcher: refuse what it matched, and report the event. */
static __always_inline int act(void)
{
    __u32 zero = 0;
    struct ev_state *s = bpf_map_lookup_elem(&avulse_ev_state, &zero);
    int refuse;

    if (!s)
        return 1;
    refuse = s->f.verdict != 0;
    if (refuse) {
        s->e.flags |= EV_BLOCKED;
        count(S_DROPPED);
    }
    submit(&s->e);
    return !refuse;
}

SEC("cgroup/connect4")
int avulse_ev_act_connect4(struct bpf_sock_addr *ctx)
{
    return act();
}

SEC("cgroup/connect6")
int avulse_ev_act_connect6(struct bpf_sock_addr *ctx)
{
    return act();
}

SEC("cgroup/post_bind4")
int avulse_ev_act_bind4(struct bpf_sock *sk)
{
    return act();
}

SEC("cgroup/post_bind6")
int avulse_ev_act_bind6(struct bpf_sock *sk)
{
    return act();
}

/* Socket ownership: the process and its name, kept for the socket's later events. */
SEC("cgroup/sock_create")
int avulse_ev_create(struct bpf_sock *sk)
{
    struct sock_info *info;

    if (sk->family != AF_INET && sk->family != AF_INET6)
        return 1;
    info = info_of(sk, 1);
    if (info) {
        info->pid = current_pid();
        current_comm(info->comm);
    }
    return 1;
}

/* SOCKET: BIND. */
static __always_inline int on_bind(struct bpf_sock *sk, int v6)
{
    struct avulse_config *cfg = live();
    struct avulse_event e = {};
    struct sock_info *info;

    if (!cfg || cfg->layer != LAYER_SOCKET)
        return 1;
    e.timestamp = bpf_ktime_get_ns();
    e.endpoint = bpf_get_socket_cookie(sk);
    e.event = EVENT_SOCKET_BIND;
    e.protocol = sk->protocol;
    e.family = v6 ? 6 : 4;
    e.local_port = sk->src_port;
    if (v6)
        CTX_IP6(e.local_addr, sk, src_ip6);
    else
        v4_mapped(e.local_addr, sk->src_ip4);
    info = info_of(sk, 1);
    owner(&e, info);
    e.pid = current_pid() ?: e.pid;
    remember(info, &e);
    return decide(sk, cfg, v6 ? (void *)&avulse_progs_bind6 : (void *)&avulse_progs_bind4, &e);
}

SEC("cgroup/post_bind4")
int avulse_ev_bind4(struct bpf_sock *sk)
{
    return on_bind(sk, 0);
}

SEC("cgroup/post_bind6")
int avulse_ev_bind6(struct bpf_sock *sk)
{
    return on_bind(sk, 1);
}

/* SOCKET: CONNECT, with the local endpoint when the socket was bound before. */
static __always_inline int on_connect(struct bpf_sock_addr *ctx, int v6)
{
    struct avulse_config *cfg = live();
    struct avulse_event e = {};
    struct sock_info *info;

    if (!cfg || cfg->layer != LAYER_SOCKET)
        return 1;
    e.timestamp = bpf_ktime_get_ns();
    e.endpoint = bpf_get_socket_cookie(ctx);
    e.event = EVENT_SOCKET_CONNECT;
    e.protocol = ctx->protocol;
    e.family = v6 ? 6 : 4;
    e.flags = EV_OUTBOUND;
    e.remote_port = __builtin_bswap16(ctx->user_port);
    if (v6)
        CTX_IP6(e.remote_addr, ctx, user_ip6);
    else
        v4_mapped(e.remote_addr, ctx->user_ip4);
    if (!v6)
        v4_mapped(e.local_addr, 0);
    info = info_of(ctx->sk, 1);
    if (info && info->family == e.family) {
        e.local_port = info->local_port;
        __builtin_memcpy(e.local_addr, info->local_addr, 16);
    }
    owner(&e, info);
    e.pid = current_pid() ?: e.pid;
    remember(info, &e);
    return decide(ctx, cfg, v6 ? (void *)&avulse_progs_connect6 : (void *)&avulse_progs_connect4,
                  &e);
}

SEC("cgroup/connect4")
int avulse_ev_connect4(struct bpf_sock_addr *ctx)
{
    return on_connect(ctx, 0);
}

SEC("cgroup/connect6")
int avulse_ev_connect6(struct bpf_sock_addr *ctx)
{
    return on_connect(ctx, 1);
}

/* SOCKET: CLOSE. FLOW: the end of a UDP socket's flows. */
SEC("cgroup/sock_release")
int avulse_ev_release(struct bpf_sock *sk)
{
    struct avulse_config *cfg = live();
    struct avulse_event e = {};
    struct sock_info *info;

    if (!cfg || (sk->family != AF_INET && sk->family != AF_INET6))
        return 1;
    e.timestamp = bpf_ktime_get_ns();
    e.endpoint = bpf_get_socket_cookie(sk);
    e.protocol = sk->protocol;
    e.family = sk->family == AF_INET6 ? 6 : 4;
    info = info_of(sk, 0);
    if (info) {
        owner(&e, info);
        e.local_port = info->local_port;
        e.remote_port = info->remote_port;
        __builtin_memcpy(e.local_addr, info->local_addr, 16);
        __builtin_memcpy(e.remote_addr, info->remote_addr, 16);
    }
    if (e.family == 4 && !e.local_addr[10])
        v4_mapped(e.local_addr, 0);
    if (e.family == 4 && !e.remote_addr[10])
        v4_mapped(e.remote_addr, 0);
    if (cfg->layer == LAYER_SOCKET) {
        e.event = EVENT_SOCKET_CLOSE;
        submit(&e);
    } else if (cfg->layer == LAYER_FLOW && e.protocol == IPPROTO_UDP) {
        e.event = EVENT_FLOW_DELETED;
        e.flags = EV_RELEASED;
        submit(&e);
    }
    return 1;
}

static __always_inline struct sock_info *from_sockops(struct avulse_event *e,
                                                      struct bpf_sock_ops *skops)
{
    struct sock_info *info;
    int v6 = skops->family == AF_INET6;

    e->timestamp = bpf_ktime_get_ns();
    e->endpoint = bpf_get_socket_cookie(skops);
    e->protocol = IPPROTO_TCP;
    e->family = v6 ? 6 : 4;
    e->local_port = skops->local_port;
    e->remote_port = __builtin_bswap32(skops->remote_port);
    if (v6) {
        CTX_IP6(e->local_addr, skops, local_ip6);
        CTX_IP6(e->remote_addr, skops, remote_ip6);
    } else {
        v4_mapped(e->local_addr, skops->local_ip4);
        v4_mapped(e->remote_addr, skops->remote_ip4);
    }
    info = info_of(skops->sk, 1);
    owner(e, info);
    remember(info, e);
    return info;
}

/* TCP: LISTEN and ACCEPT (SOCKET), ESTABLISHED and DELETED (FLOW). */
SEC("sockops")
int avulse_ev_sockops(struct bpf_sock_ops *skops)
{
    struct avulse_config *cfg = live();
    struct avulse_event e = {};
    struct sock_info *info;
    __u32 op = skops->op;
    int socket;

    if (!cfg || (skops->family != AF_INET && skops->family != AF_INET6))
        return 1;
    socket = cfg->layer == LAYER_SOCKET;
    if (!socket && cfg->layer != LAYER_FLOW)
        return 1;
    switch (op) {
    case BPF_SOCK_OPS_TCP_LISTEN_CB:
        if (!socket)
            return 1;
        from_sockops(&e, skops);
        e.event = EVENT_SOCKET_LISTEN;
        break;
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        if (socket && op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB)
            return 1;
        info = from_sockops(&e, skops);
        if (socket) {
            e.event = EVENT_SOCKET_ACCEPT;
        } else {
            e.event = EVENT_FLOW_ESTABLISHED;
            if (op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB)
                e.flags = EV_OUTBOUND;
            if (info)
                info->flags = e.flags;
            /* Ask for the state changes, to report the end of the flow. */
            bpf_sock_ops_cb_flags_set(skops,
                                      skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_STATE_CB_FLAG);
        }
        break;
    case BPF_SOCK_OPS_STATE_CB:
        if (socket || skops->args[1] != TCP_CLOSE)
            return 1;
        info = from_sockops(&e, skops);
        e.event = EVENT_FLOW_DELETED;
        if (info)
            e.flags = info->flags & EV_OUTBOUND;
        break;
    default:
        return 1;
    }
    submit(&e);
    return 1;
}

static __always_inline int ld(struct __sk_buff *skb, __u32 off, void *to, __u32 len)
{
    return bpf_skb_load_bytes(skb, off, to, len);
}

/* FLOW: the first packet of each UDP 5-tuple a socket sends or receives. cgroup_skb programs
 * see the packet from the IP header on. */
static __always_inline int udp_flow(struct __sk_buff *skb, int egress)
{
    struct avulse_config *cfg = live();
    struct avulse_event e = {};
    struct udp_flow key = {};
    struct bpf_sock *sk;
    __u8 b[2], one = 1;
    __u16 ports[2];
    __u32 l4;

    if (!cfg || cfg->layer != LAYER_FLOW)
        return 1;
    sk = skb->sk;
    if (!sk)
        return 1;
    sk = bpf_sk_fullsock(sk);
    if (!sk || sk->protocol != IPPROTO_UDP)
        return 1;
    if (ld(skb, 0, b, 1))
        return 1;
    if (b[0] >> 4 == 4) {
        __u32 src, dst;
        __u16 frag;

        if (ld(skb, 9, b + 1, 1) || b[1] != IPPROTO_UDP || ld(skb, 6, &frag, 2) ||
            (__builtin_bswap16(frag) & 0x1fff) || ld(skb, 12, &src, 4) || ld(skb, 16, &dst, 4))
            return 1;
        l4 = (b[0] & 0xf) * 4;
        e.family = 4;
        v4_mapped(e.local_addr, egress ? src : dst);
        v4_mapped(e.remote_addr, egress ? dst : src);
    } else if (b[0] >> 4 == 6) {
        if (ld(skb, 6, b + 1, 1) || b[1] != IPPROTO_UDP ||
            ld(skb, egress ? 8 : 24, e.local_addr, 16) ||
            ld(skb, egress ? 24 : 8, e.remote_addr, 16))
            return 1;
        l4 = 40;
        e.family = 6;
    } else {
        return 1;
    }
    if (ld(skb, l4 & 0x3f, ports, 4))
        return 1;
    e.local_port = __builtin_bswap16(egress ? ports[0] : ports[1]);
    e.remote_port = __builtin_bswap16(egress ? ports[1] : ports[0]);
    e.endpoint = bpf_get_socket_cookie(skb);
    key.endpoint = e.endpoint;
    __builtin_memcpy(key.remote_addr, e.remote_addr, 16);
    key.remote_port = e.remote_port;
    key.local_port = e.local_port;
    if (bpf_map_lookup_elem(&avulse_udp_flows, &key))
        return 1;
    bpf_map_update_elem(&avulse_udp_flows, &key, &one, BPF_ANY);
    e.timestamp = bpf_ktime_get_ns();
    e.event = EVENT_FLOW_ESTABLISHED;
    e.protocol = IPPROTO_UDP;
    e.flags = egress ? EV_OUTBOUND : 0;
    owner(&e, info_of(sk, 0));
    submit(&e);
    return 1;
}

SEC("cgroup_skb/egress")
int avulse_ev_egress(struct __sk_buff *skb)
{
    return udp_flow(skb, 1);
}

SEC("cgroup_skb/ingress")
int avulse_ev_ingress(struct __sk_buff *skb)
{
    return udp_flow(skb, 0);
}
