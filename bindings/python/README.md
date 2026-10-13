# avulse

Divert, modify and re-inject network packets on Linux, Windows and macOS. Avulse covers every
WinDivert feature, adds an Ethernet layer, and uses Wireshark display filters.

> **Pre-alpha: this release only reserves the name and has no API yet.** Native Python bindings
> are planned once the Linux, Windows and macOS backends exist.

- Website and filter playground: <https://ffalcinelli.github.io/avulse/>
- Guide: <https://ffalcinelli.github.io/avulse/guide/>
- Roadmap: <https://github.com/ffalcinelli/avulse/blob/main/docs/roadmap.md>
- Source: <https://github.com/ffalcinelli/avulse>

To divert packets from Python today, use [pydivert](https://pypi.org/project/pydivert/), which
runs on WinDivert (Windows) and eBPFDivert (Linux).

## License

Dual-licensed under LGPL-3.0-or-later or GPL-2.0-or-later, at your option.
