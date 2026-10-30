/* SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later */
/*
 * libavulse from C (tests/c.rs compiles and runs it): the header's layout asserts, the filter
 * helpers and the errors, without privileges; with AVULSE_BPF set, as root, a handle on lo that
 * receives, sends and batches UDP datagrams.
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "avulse.h"

static int failures;

#define CHECK(cond)                                                                           \
    do {                                                                                      \
        if (!(cond)) {                                                                        \
            fprintf(stderr, "%s:%d: %s (last error: %s)\n", __FILE__, __LINE__, #cond,         \
                    avulse_last_error());                                                     \
            failures++;                                                                       \
        }                                                                                     \
    } while (0)

static void without_privileges(void)
{
    char out[128];
    size_t needed = 0;
    avulse_handle *h = NULL;
    struct avulse_address addr;
    /* IPv4 + TCP from 10.0.0.1:40000 to 10.0.0.2:80, SYN. */
    static const unsigned char syn[40] = {
        0x45, 0, 0, 40, 0, 1, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        0x9c, 0x40, 0, 80, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 2, 0xff, 0xff, 0, 0, 0, 0,
    };

    CHECK(strlen(avulse_version()) > 0);
    CHECK(avulse_filter_check("tcp.port in {80 443}", AVULSE_SYNTAX_NATIVE, 0) == AVULSE_OK);
    CHECK(avulse_filter_check("tcp.port in {80", AVULSE_SYNTAX_NATIVE, 0) == AVULSE_E_FILTER);
    CHECK(strstr(avulse_last_error(), "tcp.port in {80") != NULL);
    CHECK(avulse_filter_check("ip.SrcAddr == 10.0.0.1", AVULSE_SYNTAX_WINDIVERT,
                              AVULSE_LAYER_NETWORK) == AVULSE_OK);
    CHECK(avulse_filter_format("tcp.port==80&&!udp", out, sizeof(out), &needed) == AVULSE_OK);
    CHECK(needed == strlen(out) + 1);
    CHECK(avulse_filter_format("tcp.port==80", out, 2, &needed) == AVULSE_E_BUFFER);
    CHECK(avulse_filter_convert("tcp.DstPort == 80", AVULSE_LAYER_NETWORK, out, sizeof(out),
                                &needed) == AVULSE_OK);
    CHECK(strstr(out, "tcp.dstport") != NULL);

    avulse_address_init(&addr, AVULSE_LAYER_NETWORK);
    CHECK(addr.version == AVULSE_ADDRESS_VERSION && addr.layer == AVULSE_LAYER_NETWORK);
    addr.outbound = true;
    CHECK(avulse_filter_eval("tcp.flags.syn == 1 and outbound", syn, sizeof(syn), false,
                             &addr) == 1);
    CHECK(avulse_filter_eval("udp", syn, sizeof(syn), false, &addr) == 0);
    CHECK(avulse_filter_eval("tcp.dstport == 80", syn, sizeof(syn), false, NULL) == 1);
    addr.layer = 42;
    CHECK(avulse_filter_eval("tcp", syn, sizeof(syn), false, &addr) == AVULSE_E_INVALID);
    avulse_address_init(&addr, AVULSE_LAYER_NETWORK);
    addr.version = 0;
    CHECK(avulse_filter_eval("tcp", syn, sizeof(syn), false, &addr) == AVULSE_E_INVALID);

    h = (avulse_handle *)1;
    CHECK(avulse_open("tcp and (", AVULSE_LAYER_NETWORK, 0, 0, &h) == AVULSE_E_FILTER);
    CHECK(h == NULL);
    h = (avulse_handle *)1;
    CHECK(avulse_open(NULL, AVULSE_LAYER_NETWORK, 0, 0, &h) == AVULSE_E_INVALID);
    CHECK(h == NULL);
    CHECK(avulse_open("tcp", AVULSE_LAYER_NETWORK, 30001, 0, &h) == AVULSE_E_INVALID);
    CHECK(avulse_open("tcp", AVULSE_LAYER_FLOW, 0, 0, &h) == AVULSE_E_INVALID);
    CHECK(avulse_open("tcp", AVULSE_LAYER_NETWORK, 0,
                      AVULSE_FLAG_SNIFF | AVULSE_FLAG_DROP, &h) == AVULSE_E_INVALID);
    CHECK(h == NULL);
    CHECK(avulse_close(NULL) == AVULSE_OK);
    CHECK(avulse_stats(NULL, NULL) == AVULSE_E_INVALID);
}

static int udp_socket(void)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(9201);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(s, (struct sockaddr *)&a, sizeof(a)) == 0);
    return s;
}

static void send_to_9201(int n)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(9201);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    for (int i = 0; i < n; i++)
        CHECK(sendto(s, "hello", 5, 0, (struct sockaddr *)&a, sizeof(a)) == 5);
    close(s);
}

/* As root: divert datagrams to 127.0.0.1:9201, then send them on. */
static void with_privileges(void)
{
    struct avulse_open_options o;
    const char *lo = "lo";
    avulse_handle *h = NULL;
    unsigned char buf[AVULSE_MAX_PACKET_LEN];
    struct avulse_address addrs[4];
    size_t lens[4], len = 0, count = 0, sent = 0;
    uint64_t v = 0;
    struct avulse_stats stats;
    const void *packets[4];
    char got[16];
    int s = udp_socket();
    struct pollfd p;

    memset(&o, 0, sizeof(o));
    o.size = sizeof(o);
    o.interfaces = &lo;
    o.interface_count = 1;
    CHECK(avulse_open_ex("udp.dstport == 9201", AVULSE_LAYER_NETWORK, &o, &h) == AVULSE_OK);
    if (!h)
        return;
    CHECK(avulse_set_param(h, AVULSE_PARAM_QUEUE_TIME, 4000) == AVULSE_OK);
    CHECK(avulse_get_param(h, AVULSE_PARAM_QUEUE_TIME, &v) == AVULSE_OK && v == 4000);
    CHECK(avulse_set_param(h, AVULSE_PARAM_QUEUE_TIME, 1) == AVULSE_E_INVALID);
    CHECK(avulse_recv(h, buf, sizeof(buf), &len, &addrs[0], 0) == AVULSE_E_TIMEOUT);

    send_to_9201(1);
    p.fd = avulse_fd(h);
    p.events = POLLIN;
    CHECK(poll(&p, 1, 2000) == 1);
    CHECK(avulse_recv(h, buf, sizeof(buf), &len, &addrs[0], 2000) == AVULSE_OK);
    CHECK(len == 33 && addrs[0].outbound && addrs[0].loopback && !addrs[0].ipv6);
    CHECK(avulse_recv(h, buf, 10, &len, &addrs[0], 0) == AVULSE_E_TIMEOUT);
    /* Diverted: nothing arrives until it is sent back. */
    CHECK(recv(s, got, sizeof(got), MSG_DONTWAIT) < 0);
    CHECK(avulse_send(h, buf, 33, &addrs[0]) == AVULSE_OK);
    usleep(100000);
    CHECK(recv(s, got, sizeof(got), MSG_DONTWAIT) == 5);

    /* Three at once, sent back at once. */
    send_to_9201(3);
    usleep(200000);
    CHECK(avulse_recv_batch(h, buf, sizeof(buf), addrs, lens, 4, &count, 2000) == AVULSE_OK);
    CHECK(count == 3);
    for (size_t i = 0, at = 0; i < count; at += lens[i], i++)
        packets[i] = buf + at;
    CHECK(avulse_send_batch(h, packets, lens, addrs, count, &sent) == AVULSE_OK && sent == 3);
    CHECK(avulse_stats(h, &stats) == AVULSE_OK && stats.diverted >= 4 && stats.dropped == 0);
    usleep(100000);
    for (int i = 0; i < 3; i++)
        CHECK(recv(s, got, sizeof(got), MSG_DONTWAIT) == 5);

    /* A packet too large for the buffer is dropped, with its length. */
    send_to_9201(1);
    CHECK(avulse_recv(h, buf, 10, &len, &addrs[0], 2000) == AVULSE_E_BUFFER && len == 33);

    CHECK(avulse_shutdown(h, AVULSE_SHUTDOWN_BOTH) == AVULSE_OK);
    CHECK(avulse_recv(h, buf, sizeof(buf), &len, &addrs[0], 0) == AVULSE_E_SHUTDOWN);
    CHECK(avulse_send(h, buf, 33, &addrs[0]) == AVULSE_E_SHUTDOWN);
    CHECK(avulse_close(h) == AVULSE_OK);
    close(s);
}

int main(void)
{
    without_privileges();
    if (getenv("AVULSE_BPF"))
        with_privileges();
    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    puts("ok");
    return 0;
}
