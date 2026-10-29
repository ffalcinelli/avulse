# Metadata fields

Besides the packet bytes, a diverter knows where a packet comes from and goes to. Avulse exposes
that as extension fields, which Wireshark does not have. They follow WinDivert's model of layers
and events.

## Flags

Bare, these test that the value is true:

| Field | True when |
| --- | --- |
| `inbound` | the packet is inbound |
| `outbound` | the packet is outbound |
| `loopback` | the packet is on a loopback interface |
| `impostor` | another handle injected the packet |
| `fragment` | the packet is an IP fragment |

```filter
outbound and not loopback and not impostor
```

## Interface

| Field | Type | Value |
| --- | --- | --- |
| `iface` | string | interface name (Wireshark's `frame.interface_name` is the same value) |
| `ifidx` | integer | interface index |
| `subifidx` | integer | sub-interface index |

```filter
iface == "eth0" or upper(iface) == "WLAN0"
```

## Layer and event

`layer` is the layer of the handle, and `event` what happened. Both take symbolic names:

| Layer | Sees |
| --- | --- |
| `network` | IP packets to and from the local host |
| `network-forward` | IP packets being forwarded |
| `ethernet` | Ethernet frames, including non-IP traffic (new in Avulse) |
| `flow` | flows being established and deleted (no packet) |
| `socket` | socket operations (no packet) |
| `reflect` | other handles being opened and closed |

| Events | Layer |
| --- | --- |
| `packet` | `network`, `network-forward`, `ethernet` |
| `established`, `deleted` | `flow` |
| `bind`, `connect`, `listen`, `accept`, `close` | `socket` |
| `open` (`reflect-open`), `reflect-close` | `reflect` |

```filter
event == connect and remote.port == 443
```

## Flows, sockets and processes

The `flow` and `socket` layers have no packet, so their filters use these fields instead of
`ip.*` and `tcp.*`:

| Field | Type | Value |
| --- | --- | --- |
| `local.addr`, `remote.addr` | IP address (v4 or v6) | the endpoints |
| `local.port`, `remote.port` | integer | the ports |
| `protocol` | integer | the transport protocol (`tcp`, `udp`, …) |
| `process.pid` | integer | the process ID |
| `process.name` | string | the process name |
| `endpoint.id`, `parent.endpoint.id` | integer | WinDivert's endpoint identifiers |

```filter
process.name == "curl" and protocol == tcp and remote.addr != 127.0.0.1
```

The process name is the platform's: on Linux the task's name (`comm`, at most 15 bytes, `curl`),
on Windows the image's file name (`curl.exe`). Either way, at most its first 32 bytes are kept.

On packet layers, `local.*` and `remote.*` are filled from the headers and the direction, and
`protocol` is the transport protocol after any IPv6 extension headers.

## Time, priority and hash

These come from WinDivert, and are mostly useful in [WinDivert filters](windivert.md):

| Field | Type | Value |
| --- | --- | --- |
| `timestamp` | signed integer | the packet or event timestamp, in the backend's units |
| `priority` | signed integer | the handle's priority; at the `reflect` layer, the priority of the handle the event is about |
| `random8`, `random16`, `random32` | integer | bits of a deterministic per-packet hash the backend computes, as WinDivert's fields of the same names |

```filter
timestamp > 0 and random8 < 128
```
