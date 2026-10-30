#!/usr/bin/env python3
"""Generate crates/windivert-compat/src/tests/vectors.rs: what WinDivert's own helpers return for
WinDivertHelperHashPacket, WinDivertHelperCalcChecksums and WinDivertHelperEvalFilter (the
`random*` fields, and the packet and address checks) on a corpus of packets, and the serialized
filter objects of WinDivertHelperCompileFilter (REFLECT's data) for WinDivert's filters and more.

It compiles a small C driver against ebpfdivert's vendored copy of WinDivert's helper code
(src/wd/wd_port.c, which builds on Linux without root) and runs it.

Usage: python3 scripts/gen_compat_vectors.py [path/to/ebpfdivert]

The default is ../ebpfdivert. Needs a C compiler (`CC`, default `cc`).
"""

import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "crates" / "windivert-compat" / "src" / "tests" / "vectors.rs"

sys.path.insert(0, str(ROOT / "scripts"))
import gen_windivert_vectors  # noqa: E402

DRIVER = r"""
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wd.h"

static int unhex(const char *s, uint8_t *out) {
    int n = 0;
    while (isxdigit((unsigned char)s[0]) && isxdigit((unsigned char)s[1])) {
        unsigned v;
        sscanf(s, "%2x", &v);
        out[n++] = (uint8_t)v;
        s += 2;
    }
    return n;
}

int main(void) {
    static char line[1 << 20];
    static uint8_t pkt[1 << 18];
    while (fgets(line, sizeof(line), stdin)) {
        char *p = line + 2;
        if (line[0] == 'H') {
            unsigned long long seed = strtoull(p, &p, 10);
            int n = unhex(p + 1, pkt);
            printf("%llu\n", (unsigned long long)wd_hash_packet(pkt, n, seed));
        } else if (line[0] == 'C') {
            unsigned long long flags = strtoull(p, &p, 10);
            int n = unhex(p + 1, pkt), i;
            uint8_t addr[80] = {0};
            int r = wd_calc_checksums(pkt, n, addr, flags);
            uint32_t bits;
            memcpy(&bits, addr + 8, 4);
            printf("%d %u ", r, bits);
            for (i = 0; i < n; i++) printf("%02x", pkt[i]);
            printf("\n");
        } else if (line[0] == 'O') {
            unsigned layer = strtoul(p, &p, 10);
            char *filter = p + 1;
            struct wd_filter *f = NULL;
            const char *err;
            unsigned pos;
            static char obj[1 << 16];
            filter[strcspn(filter, "\n")] = 0;
            if (wd_filter_compile(filter, layer, &f, &err, &pos) != 0 ||
                wd_filter_serialize(f, obj, sizeof(obj)) < 0) {
                printf("ERR\n");
            } else {
                printf("%s\n", obj);
            }
            wd_filter_free(f);
        } else if (line[0] == 'E') {
            long long ts = strtoll(p, &p, 10);
            unsigned layer = strtoul(p, &p, 10), ipv6 = strtoul(p, &p, 10);
            int n = unhex(p + 1, pkt);
            char *filter = strchr(p + 1, ' ') + 1;
            uint8_t addr[80] = {0};
            uint32_t bits = layer | (ipv6 << 20) | (1u << 17); /* outbound */
            filter[strcspn(filter, "\n")] = 0;
            memcpy(addr, &ts, 8);
            memcpy(addr + 8, &bits, 4);
            printf("%d\n", wd_eval_filter_string(filter, n ? pkt : NULL, n, addr));
        }
    }
    return 0;
}
"""


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def ipv4(proto, payload, *, frag=0, total=None, ihl=5, opts=b""):
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x40 | ihl,
        0,
        total if total is not None else 4 * ihl + len(payload),
        0x1234,
        frag,
        64,
        proto,
        0xBEEF,
        bytes([10, 0, 0, 1]),
        bytes([10, 0, 0, 2]),
    )
    return hdr + opts + payload


def ipv6(nxt, payload, *, plen=None):
    src = bytes(15) + b"\1"
    dst = bytes([0x20, 1, 0xD, 0xB8] + [0] * 11 + [2])
    return (
        struct.pack("!IHBB", 0x60012345, plen if plen is not None else len(payload), nxt, 64)
        + src
        + dst
        + payload
    )


def tcp(payload=b"", *, doff=5, opts=b""):
    return struct.pack("!HHIIBBHHH", 40000, 80, 1, 2, doff << 4, 0x18, 1024, 0xAAAA, 0) + opts + payload


def udp(payload=b""):
    return struct.pack("!HHHH", 53000, 53, 8 + len(payload), 0xAAAA) + payload


def icmp(payload=b""):
    return struct.pack("!BBHHH", 8, 0, 0xAAAA, 7, 1) + payload


def corpus(wd_packets):
    """WinDivert's packets, then cases at the edges of its parser."""
    out = list(wd_packets)
    data = b"hello, world"
    out += [
        ipv4(6, tcp(data)),
        ipv4(17, udp(data)),
        ipv4(1, icmp(data)),
        ipv6(6, tcp(data)),
        ipv6(17, udp(data)),
        ipv6(58, icmp(data)),
        # Truncated: the IP length is longer than the packet.
        ipv4(17, udp(data), total=100),
        ipv6(6, tcp(data), plen=200),
        # Longer than the IP length: the rest is not checksummed.
        ipv4(17, udp(data)) + b"trailer!",
        # Fragments: the first one (MF), a later one.
        ipv4(17, udp(data), frag=0x2000),
        ipv4(17, data, frag=0x0010),
        ipv6(44, struct.pack("!BBHI", 17, 0, 0x0001, 99) + udp(data)),
        ipv6(44, struct.pack("!BBHI", 17, 0, 0x0100, 99) + data),
        # IPv6 extension headers: hop-by-hop, destination options, routing, AH.
        ipv6(0, struct.pack("!BB6x", 60, 0) + struct.pack("!BB6x", 43, 0) + struct.pack("!BBBB4x", 51, 0, 0, 0)
             + struct.pack("!BB10x", 6, 1) + tcp(data)),
        # TCP options, and a data offset below 5. (Not one longer than the packet: WinDivert then
        # checksums the whole header it claims, reading past the end of the packet.)
        ipv4(6, tcp(data, doff=7, opts=bytes([2, 4, 5, 0xB4, 1, 1, 1, 0]))),
        ipv4(6, tcp(doff=4)),
        # IPv4 options.
        ipv4(17, udp(data), ihl=6, opts=bytes([1, 1, 1, 0])),
        # A UDP checksum that comes out as 0 (written 0xffff): found by search below.
        # Short or broken: no transport header, bad IHL, unknown version, too short.
        ipv4(6, b"\0" * 10),
        ipv4(17, b"\0" * 4),
        ipv4(1, b"\0" * 4),
        ipv4(99, data),
        ipv6(58, b"\0" * 4),
        ipv6(1, icmp(data)),
        ipv4(58, icmp(data)),
        bytes([0x44]) + ipv4(17, udp(data))[1:],
        bytes([0x50]) + ipv4(17, udp(data))[1:],
        b"\x45\x00\x00",
        b"",
    ]
    # A payload whose UDP checksum is 0.
    for i in range(1 << 16):
        p = ipv4(17, udp(struct.pack("!H", i)))
        pseudo = p[12:20] + struct.pack("!BBH", 0, 17, 10)
        u = bytearray(p[20:])
        u[6:8] = b"\0\0"
        if csum(pseudo + bytes(u)) == 0:
            out.append(p)
            break
    return out


# Filters at every layer whose WinDivert object is recorded, besides WinDivert's vectors.
OBJECT_FILTERS = [
    (0, "true"),
    (0, "false"),
    (0, "zero"),
    (0, "not true"),
    (0, "impostor or loopback == 2"),
    (0, "fragment and length > 100"),
    (0, "packet32[-4b] == 0x34353637 and tcp.Payload[-1] == 10 and udp.Payload16[2b] != 0"),
    (0, "random8 < 128 or random32 >= 5"),
    (0, "ipv6.SrcAddr == ::1 or ip.SrcAddr == 10.0.0.1 or ipv6.DstAddr > 2001:db8::"),
    (0, "ip.TOS < 0 or tcp.Syn <= 1 or udp.Length > 70000"),
    (0, "(tcp? tcp.DstPort == 80: (udp? udp.DstPort == 53: icmp))"),
    (0, "(false? tcp: udp) and (true? ip: ipv6)"),
    (0, "timestamp > -5 and ifIdx == 3 and subIfIdx != 0"),
    (1, "ip.TTL < 5 or ipv6.HopLimit < 5"),
    (2, "tcp and remotePort == 443"),
    (2, "localAddr == ::1 or remoteAddr == 10.0.0.1"),
    (2, "processId == 1234 and endpointId > 5 and parentEndpointId != 0x100000000"),
    (2, "event == ESTABLISHED and loopback"),
    (3, "event == CONNECT and remotePort == 9306"),
    (3, "outbound and (tcp ? localPort < 1024 : udp)"),
    (3, "protocol == TCP or event == CLOSE"),
    (4, "event == OPEN and priority == 1234"),
    (4, "layer == NETWORK or priority < -100"),
    (4, "processId >= 10 and timestamp != 0"),
]


def run(driver, lines):
    r = subprocess.run([driver], input="\n".join(lines) + "\n", capture_output=True, text=True, check=True)
    return r.stdout.splitlines()


def main():
    ebd = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT.parent / "ebpfdivert"
    arrays, packets, tests = gen_windivert_vectors.parse((ebd / "tests" / "wd_vectors.c").read_text())
    names = list(packets)
    wd_packets = [arrays[packets[n]] for n in names]
    pkts = corpus(wd_packets)
    cc = os.environ.get("CC", "cc")
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "driver.c"
        exe = Path(tmp) / "driver"
        src.write_text(DRIVER)
        wd = ebd / "src" / "wd"
        subprocess.run(
            [cc, "-O2", "-fno-strict-aliasing", "-w", f"-I{ebd / 'include'}", f"-I{ebd / 'src'}", f"-I{wd}", f"-I{wd / 'compat'}",
             str(src), str(wd / "wd_port.c"), "-o", str(exe)],
            check=True,
        )
        seeds = [0, 1, 0x0123456789ABCDEF]
        h_in = [(i, s) for i in range(len(pkts)) for s in seeds]
        hashes = run(exe, [f"H {s} {pkts[i].hex()}" for i, s in h_in])
        flag_sets = [0, 1, 2, 4, 8, 16, 31]
        c_in = [(i, f) for i in range(len(pkts)) for f in flag_sets]
        sums = run(exe, [f"C {f} {pkts[i].hex()}" for i, f in c_in])
        # The random* vectors at several timestamps, and the packet and address checks.
        e_in = []
        for filt, pkt, _ in tests:
            if "random" in filt:
                for ts in [0, 1, 123456789, -5]:
                    e_in.append((filt, names.index(pkt), ts, 0, None))
        for i, p in enumerate(pkts):
            for ipv6_flag in (0, 1):
                e_in.append(("true", i, 0, 0, ipv6_flag))
        for layer in (2, 3, 4):
            e_in.append(("true", None, 0, layer, 0))
            e_in.append(("true", 0, 0, layer, 0))
        e_lines = []
        for filt, i, ts, layer, ipv6_flag in e_in:
            data = pkts[i] if i is not None else b""
            if ipv6_flag is None:
                ipv6_flag = 1 if data and data[0] >> 4 == 6 else 0
            e_lines.append(f"E {ts} {layer} {ipv6_flag} {data.hex() or '-'} {filt}")
        evals = run(exe, e_lines)
        o_in = [(0, filt) for filt in dict.fromkeys(f for f, _, _ in tests)] + OBJECT_FILTERS
        objects = run(exe, [f"O {layer} {filt}" for layer, filt in o_in])

    out = [
        "//! What WinDivert's helpers return, from ebpfdivert's vendored copy of WinDivert 2.2's helper",
        "//! code. WinDivert's packets are under its LGPL-3.0-or-later / GPL-2.0-or-later dual license.",
        "//!",
        "//! Generated by `scripts/gen_compat_vectors.py`. Do not edit.",
        "",
        "/// The packets: WinDivert's test packets, then edge cases of its parser.",
        "pub(super) const PACKETS: &[&[u8]] = &[",
    ]
    for p in pkts:
        out.append("    &[")
        for k in range(0, len(p), 16):
            out.append("        " + ", ".join(f"0x{b:02x}" for b in p[k : k + 16]) + ",")
        out.append("    ],")
    out += [
        "];",
        "",
        "/// `WinDivertHelperHashPacket`: packet, seed, hash.",
        "pub(super) const HASHES: &[(usize, u64, u64)] = &[",
    ]
    out += [f"    ({i}, {s:#x}, {int(h):#018x})," for (i, s), h in zip(h_in, hashes)]
    out += [
        "];",
        "",
        "/// `WinDivertHelperCalcChecksums`: packet, flags, result (0 or a negative errno), the address's",
        "/// bitfield word, and the bytes that changed (offset, new value).",
        "pub(super) type Checksum = (usize, u64, i32, u32, &'static [(usize, u8)]);",
        "pub(super) const CHECKSUMS: &[Checksum] = &[",
    ]
    for (i, f), line in zip(c_in, sums):
        r, bits, data = line.split(" ")
        new = bytes.fromhex(data)
        diff = ", ".join(f"({k}, 0x{b:02x})" for k, (a, b) in enumerate(zip(pkts[i], new)) if a != b)
        out.append(f"    ({i}, {f}, {r}, {int(bits):#x}, &[{diff}]),")
    out += [
        "];",
        "",
        "/// `WinDivertHelperEvalFilter` with an outbound address: filter, packet (`None` for no packet),",
        "/// timestamp, layer, the address's IPv6 flag, and the result (1, 0, or a negative errno).",
        "pub(super) type Eval = (&'static str, Option<usize>, i64, u8, bool, i32);",
        "pub(super) const EVALS: &[Eval] = &[",
    ]
    for (filt, i, ts, layer, _), line, l in zip(e_in, evals, e_lines):
        ipv6_flag = l.split(" ")[3] == "1"
        idx = "None" if i is None else f"Some({i})"
        out.append(f'    ("{filt}", {idx}, {ts}, {layer}, {str(ipv6_flag).lower()}, {line}),')
    out += [
        "];",
        "",
        "/// `WinDivertHelperCompileFilter`'s serialized objects: layer, filter, object (without its NUL).",
        "pub(super) const OBJECTS: &[(u8, &str, &str)] = &[",
    ]
    for (layer, filt), obj in zip(o_in, objects):
        assert obj != "ERR", filt
        out.append(f'    ({layer}, "{filt}", "{obj}"),')
    out += ["];", ""]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(out))
    print(f"wrote {OUT}: {len(pkts)} packets, {len(h_in)} hashes, {len(c_in)} checksums, {len(e_in)} evaluations, {len(o_in)} objects")


if __name__ == "__main__":
    main()
