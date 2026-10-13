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

On packet layers, `local.*` and `remote.*` are filled from the headers and the direction, and
`protocol` is the transport protocol after any IPv6 extension headers.
