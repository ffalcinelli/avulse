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

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_skb_load_bytes)(const void *skb, __u32 offset, void *to,
                                  __u32 len) = (void *)BPF_FUNC_skb_load_bytes;
static long (*bpf_tail_call)(void *ctx, void *prog_array_map,
                             __u32 index) = (void *)BPF_FUNC_tail_call;

#endif
