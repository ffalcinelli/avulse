"""Divert, modify and re-inject network packets on Linux, Windows and macOS.

Avulse covers every [WinDivert](https://reqrypt.org/windivert.html) feature, adds an Ethernet
layer, and filters packets with [Wireshark display
filters](https://ffalcinelli.github.io/avulse/guide/filters/overview.html).

**Status: pre-alpha.** This release only reserves the name on PyPI and has no API yet. The
native bindings will arrive after the platform backends; see the
[roadmap](https://github.com/ffalcinelli/avulse/blob/main/docs/roadmap.md). Until then,
[pydivert](https://pypi.org/project/pydivert/) diverts packets from Python on Windows and Linux.

- Website and filter playground: <https://ffalcinelli.github.io/avulse/>
- Guide: <https://ffalcinelli.github.io/avulse/guide/>
- Source: <https://github.com/ffalcinelli/avulse>
"""

__all__ = ["__version__"]

__version__ = "0.0.0"
"""The package version."""
