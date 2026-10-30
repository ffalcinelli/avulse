/* SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later */
/*
 * The few libbpf conventions the programs use, declared here so that building them needs only
 * clang and the kernel UAPI headers.
 */
#ifndef AVULSE_HELPERS_H
#define AVULSE_HELPERS_H

#include <linux/bpf.h>

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name
#undef __always_inline
#define __always_inline inline __attribute__((always_inline))
/* Hides a value from the compiler's reasoning, so that it keeps the checks the verifier needs. */
#define barrier_var(var) asm volatile("" : "+r"(var))

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_skb_load_bytes)(const void *skb, __u32 offset, void *to,
                                  __u32 len) = (void *)BPF_FUNC_skb_load_bytes;
static long (*bpf_tail_call)(void *ctx, void *prog_array_map,
                             __u32 index) = (void *)BPF_FUNC_tail_call;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size,
                                    __u64 flags) = (void *)BPF_FUNC_ringbuf_reserve;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)BPF_FUNC_ringbuf_submit;
static void (*bpf_ringbuf_discard)(void *data, __u64 flags) = (void *)BPF_FUNC_ringbuf_discard;
static long (*bpf_redirect)(__u32 ifindex, __u64 flags) = (void *)BPF_FUNC_redirect;
static long (*bpf_fib_lookup)(void *ctx, struct bpf_fib_lookup *params, int plen,
                              __u32 flags) = (void *)BPF_FUNC_fib_lookup;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value,
                                   __u64 flags) = (void *)BPF_FUNC_map_update_elem;
static __u64 (*bpf_get_socket_cookie)(void *ctx) = (void *)BPF_FUNC_get_socket_cookie;
static void *(*bpf_sk_storage_get)(void *map, void *sk, void *value,
                                   __u64 flags) = (void *)BPF_FUNC_sk_storage_get;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)BPF_FUNC_get_current_pid_tgid;
static long (*bpf_get_current_comm)(void *buf, __u32 size) = (void *)BPF_FUNC_get_current_comm;
static long (*bpf_sock_ops_cb_flags_set)(struct bpf_sock_ops *skops,
                                         int flags) = (void *)BPF_FUNC_sock_ops_cb_flags_set;
static struct bpf_sock *(*bpf_sk_fullsock)(struct bpf_sock *sk) = (void *)BPF_FUNC_sk_fullsock;

#endif
