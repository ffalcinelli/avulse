# Spike C: macOS, on GitHub's runners

**Verdict: partly answered. No blocker for the bpf backend (Phase 6, Step 31). The provider's
behaviour is still unmeasured, and cannot be measured on a runner. With SIP off, a script gets
the extension approved (finding 10), the filter enabled (finding 12) and the provider registered
(finding 13). But AMFI will not let launchd run an ad-hoc signed provider that carries the
restricted entitlement, and sysextd will not take one without it (findings 14 and 15). It needs
a Developer ID, or a Mac with AMFI turned off.** There is
no Mac, so the spike ran on GitHub Actions' macOS runners (macOS 26 and 15 on Apple silicon,
macOS 26 on Intel). They are VMs with root, and **SIP is off** on all of them. `/dev/bpf`
captures and injects as the roadmap assumes, but only outbound. Two paths deliver inbound
reinjection on any interface: a raw socket and `utun`. A `NEFilterPacketProvider` system
extension built around avulse's Rust static library builds as a universal binary. Signed ad hoc
with the restricted entitlements, it reaches `activated waiting for user` in `sysextd`. Nothing
on a headless runner approves it, so the provider's packet format, throughput and delay
semantics are still open (finding 6).

Date: 2026-10-21. Code: `spikes/macos` (outside the workspace) and
`.github/workflows/macos-spike.yml`. Runs 39632708214, 39634020355 (cancelled: it hung) and
39639964578. Each job uploads its `report.jsonl` (one JSON object per result).

## What was built

- **`probe`**, a Rust binary with four probes:
  - `env`: OS, SIP, system extensions, bpf sysctls, which pf rules parse, and the SDK's
    NetworkExtension headers;
  - `bpf`: device settings, then injection on a `feth0`/`feth1` pair (`ifconfig fethN create`,
    `peer`), on `lo0` and on the default interface, then write and capture rates;
  - `inject`: inbound reinjection without a peer interface, through a raw IP socket and a `utun`
    device;
  - `bench`: the IR evaluator and the bytecode interpreter on a mixed corpus.
- **`sysext/`**: a Swift `NEFilterPacketProvider` whose packet handler compiles
  `tcp.dstport == 443` with the Rust library and runs the bytecode on every packet. It delays
  the matches and allows them again from another queue, as a diverting handle would. A host app
  self-tests the library, asks `OSSystemExtensionManager` to activate the extension, and, if that
  works, enables it through `NEFilterManager` and times HTTPS requests. `build.sh` builds the
  Rust library for both architectures (joined with `lipo`), the Swift code with `swiftc` (no
  Xcode project), and two bundles signed ad hoc: one with the restricted entitlements, one
  without.

## Findings

1. **The runners.** Apple M1 (virtual, 3 CPUs, 7 GiB) or an Intel i7-8700B (4 CPUs, 14 GiB),
   `kern.hv_vmm_present` = 1. SIP is disabled, `DevToolsSecurity` is on, there is no MDM
   enrolment, and no system extension is installed. pf is present but disabled.
2. **bpf captures and injects, outbound only.**
   - Setup: 4 devices exist, more are cloned on demand (`debug.bpf_maxdevices` 256).
     `BIOCSBLEN` takes 16 MiB, past `debug.bpf_maxbufsize` (512 KiB), up to
     `debug.bpf_bufsize_cap` (32 MiB). The DLT is `EN10MB` on `feth` and `NULL` on `lo0`.
     Records start with an 18-byte `bpf_hdr` (a 32-bit `timeval`), 4-byte aligned.
     `BIOCSHDRCMPLT` keeps a spoofed source MAC.
   - A frame written on `feth0` arrives at `feth1` as received. An ICMP echo request from a
     made-up peer was answered in 0.12 to 1 ms. A UDP datagram reached a bound socket, which saw
     `feth1` as the interface. A second bpf on the writing interface sees the frame too.
   - A frame written to `lo0` is accepted (the write returns its length) but never delivered.
   - A frame written on the default interface to its own MAC and IP is not looped back to the
     stack.
   - So bpf reinjects outbound frames at L2, and inbound frames only on an interface that has a
     peer.
3. **Inbound reinjection works through a raw socket and through `utun`, at L3.**
   - **Raw socket.** A raw IP socket (`IP_HDRINCL`) needs `ip_len` and `ip_off` in **host**
     byte order (network order fails with `EINVAL`). It delivers a datagram to a local address,
     from any source (93.184.216.34 to the default interface's address). The receiver sees the
     interface that owns the address, not `lo0`.
   - **`utun`.** As root, with no entitlement (`PF_SYSTEM`/`SYSPROTO_CONTROL`,
     `com.apple.net.utun_control`), it delivers to the addresses of every interface, from any
     source, and the receiver sees the `utun` interface.
   - The raw socket is the better inbound path: the interface is right.
4. **pf has no divert sockets.** `divert-to` and `divert-packet` are syntax errors. `route-to`,
   `dup-to`, `dummynet` and `rdr` parse. A pf-based NETWORK_FORWARD can only redirect, as the
   roadmap's matrix says.
5. **The filter engine.** Release builds over an 8-packet mix, per packet (macos-15, macos-26,
   macos-26-intel, ubuntu-latest):

   | Filter | Eval (ns) | Bytecode (ns) |
   | --- | --- | --- |
   | `tcp.port == 443` | 16 / 56 / 66 / 22 | 91 / 119 / 344 / 123 |
   | a 51-port set | 62 / 84 / 117 / 56 | 272 / 351 / 651 / 430 |
   | `tcp.payload contains "GET "` | 416 / 574 / 1267 / 515 | 504 / 775 / 1606 / 608 |
   | a WinDivert filter | 41 / 36 / 158 / 51 | 195 / 232 / 505 / 267 |

   Parsing costs 9 to 30 ns. Even interpreted, a filter is well under a microsecond per packet.
   But the **bytecode interpreter is 2 to 7 times slower than the IR evaluator** on every
   platform, for every filter but the payload search. `exec::run` copies its two operand registers (`Vals`, about 170 bytes each) on
   every instruction, and zeroes a 16-register file on every call. Phase 5 (the Windows driver
   runs the same interpreter) should make it borrow its operands.
6. **The system extension.**
   - It builds: the Rust static library links into Swift with `-lSystem -lc -lm` only, as a
     universal (arm64 and x86_64) binary, and the self-test runs it from Swift.
   - With SIP off, AMFI lets the app run ad hoc signed *with*
     `com.apple.developer.system-extension.install` and the Network Extension entitlement.
     `sysextd` validates and stages the extension, and stops at
     `activated_waiting_for_user`.
   - Without the entitlement, activation fails with `OSSystemExtensionErrorDomain` code 2,
     "Missing entitlement".
   - `systemextensionsctl developer on` does not complete headless: it hung for 35 minutes in
     the second run, and was killed after 30 s in the third.
   - So the step that is left is the approval in System Settings, then the provider's behaviour.
7. **The SDK's contract** (`NEFilterPacketProvider.h`, SDK 26.5). The handler gets
   `packetBytes`/`packetLength`, the `nw_interface_t` and the direction. It returns allow, drop
   or delay; a delayed packet is held until `allowPacket:` or dropped when released. It may run
   on several threads at once. The header says "frames" once, but nothing states whether the
   bytes start at the link-layer header. The provider logs its first 30 packets' leading bytes
   for when it runs.

## Phase 6's runs (2026-10-30)

Runs 41025892732, 41026701134, 41027504030 and 41028368933, on macOS 15.7 and 26.6 (Apple
silicon and Intel). Step 31a (the `meta` probe) answered what the bpf backend needed. Step 32
(`activate.sh`) tried to get the extension running.

8. **Direction.**
   - `BIOCSDIRECTION` (`_IOW('B', 139)`, values `BPF_D_IN` 1, `BPF_D_OUT` 2, `BPF_D_INOUT` 3,
     the default) works on every runner. It is XNU's, and the SDK's `net/bpf.h` leaves it out.
     A device set to IN sees only the inbound datagram, one set to OUT only the outbound one.
   - On `lo0`, only the OUT device sees a datagram, once.
   - `BIOCSEXTHDR` (the extended header with direction, PID and command name) fails with
     EINVAL.
   - `bh_hdrlen` is 20 on `lo0`, not 18: bpf pads the header so that the network header is
     aligned.
9. **utun and IPv6.**
   - A bpf device on `utun` reports `DLT_NULL`, with the family in host byte order.
   - IPv6 inbound fails through a raw socket: the SDK has no `IPV6_HDRINCL`, and option 36 is
     accepted but does nothing.
   - It also fails through a utun without an IPv6 address.
   - It works through a utun that has one (`ifconfig utunN inet6 fd78::1 fd78::2 prefixlen
     128`). The receiver sees the datagram from its real source, on the utun.
10. **Approving the extension works.** With SIP off, `activate.sh` changes the extension's
    `state` from `activated_waiting_for_user` to `activated_enabled` in
    `/Library/SystemExtensions/db.plist` and restarts sysextd (`launchctl kickstart -k
    system/com.apple.sysextd`).
    - `systemextensionsctl list` then shows it activated and enabled.
    - The pending request fails (`OSSystemExtensionErrorDomain` 1), but a new one completes at
      once.
    - The "would like to use a new network extension" notice is an alert of
      `UserNotificationCenter`, which a System Events click dismisses.
    - The runners grant accessibility to `/bin/bash` and `osascript`, and screen capture to
      `/bin/bash`, so `screencapture` works. The screenshots are uploaded with the report.
11. **Enabling the filter is refused.** `NEFilterManager.saveToPreferences` fails with
    `NEFilterErrorDomain` 5, "permission denied", in every variant tried:
    - the app run as itself, or as root;
    - with `system.services.networkextension.filtering` and the other networking rights set to
      `allow` in the authorization database.

    nehelper logs `entitled = 0, hasProviderPermission = 0`, then "Failed to obtain
    authorization right for 3: no authorization provided": an ad-hoc signature has no team ID,
    and nehelper does not count the app as entitled. `NEFilterManager` does not respond to
    `setAuthorization:`, which `NEVPNManager` has.
12. **An authorization gets past nehelper** (runs 41028368933, 41028825224).
    - `NEConfigurationManager` has `setAuthorization:`, `sharedManager` and
      `sharedManagerForAllUsers`.
    - The app sets an authorization for `system.services.networkextension.filtering` on both
      shared managers, and on the filter manager's `_configurationManager` ivar, through the
      Objective-C runtime.
    - `saveToPreferences` then succeeds on macOS 15 and 26 (Apple silicon), and authd logs
      nehelper authorizing the right for the app. On `macos-26-intel` the call never returns.
13. **The provider is not registered** (run 41029887542). nesessionmanager starts the filter
    session, then logs "Found 0 registrations for com.github.ffalcinelli.avulse.spike.filter
    (com.apple.networkextension.filter-packet)" and falls back to looking for an app
    extension.
    - Approving through the database skips the launchd job that sysextd makes on activation.
    - The entry's `additionalLaunchdPlistEntries` (an `NSKeyedArchiver` archive) holds the
      job's `MachServices` and a `com.apple.networkextension.provider.matching` launch event.
    - `launchd_job.py` makes the same job from the staged bundle.
14. **Registered, but not started** (run 41031016569).
    - With the job bootstrapped, nesessionmanager finds 2 registrations, creates the plugin and
      sends the start command. The provider never checks in, and the session stays
      "connecting".
    - Meanwhile the filter's default drop holds traffic: curl took 30 to 75 s with the filter
      enabled, against 0.16 s without.
    - Run 41032129926: nesessionmanager makes its own launchd job for the provider
      (`NetworkExtension.<identifier>.0.0.0.1`), and launchd fails to start it: "Could not find
      and/or execute program …: 13: Permission denied".
    - amfid logs "The file is adhoc signed but contains restricted entitlements" for these
      binaries. The app runs regardless; the extension's daemon does not.
15. **The wall** (run 41033234741). Without the restricted entitlement, sysextd refuses the
    extension at activation (`OSSystemExtensionErrorDomain` 9: it "does not appear to belong
    to any extension categories"). With it, AMFI keeps launchd from running the provider. So
    an ad-hoc signed provider cannot run on a runner, SIP or not. It takes either:
    - a Developer ID with the entitlement;
    - or a Mac booted with `amfi_get_out_of_my_way=1`, which needs a reboot that a runner
      cannot do.

## What Phase 6 must take into account

- Inbound modify (drop and reinject) has a path: the raw socket, with host-order `ip_len` and
  `ip_off`, which delivers on the right interface. Outbound goes out through bpf at L2. Neither
  needs the system extension, so the daemon can do it.
- `NEFilterPacketProvider` gives allow, drop and delay-then-allow. It has no way to send other
  bytes, so modify is drop plus reinject, as the matrix says.
- Build: plain `swiftc` and `lipo` are enough; no Xcode project is needed. Signing and
  notarization remain owner actions.
- The bytecode interpreter's per-instruction copies (finding 5).

## Left open, and how to close it

- **The provider at work** (frame level, throughput, delay latency). `activate.sh` gets as far
  as launchd starting the provider (findings 10 to 15). What is left needs either:
  - a Developer ID with the Network Extension entitlement (owner action), with which none of the
    workarounds is needed;
  - or a Mac with SIP off and `nvram boot-args="amfi_get_out_of_my_way=1"`, rebooted, where
    `activate.sh` should take it the rest of the way.
- **NETWORK_FORWARD through pf** (`route-to` to a `utun`?) was not tried.
