# Python

The `avulse` package on [PyPI](https://pypi.org/project/avulse/) is a **placeholder**: version
0.0.0 reserves the name and has no API yet.

```console
$ pip install avulse
```

Native Python bindings are planned for Phase 7 of the [roadmap](../project/design.md#roadmap),
either with PyO3 or over the C ABI. Until then, the way to divert packets from Python is
[pydivert](https://github.com/ffalcinelli/pydivert), which runs on WinDivert on Windows and on
[ebpfdivert](https://github.com/ffalcinelli/ebpfdivert) on Linux. Avulse's WinDivert-compatible
shim is meant to let pydivert run on Avulse unchanged.

The [Python API reference](https://ffalcinelli.github.io/avulse/api/python/) is generated from the
package, and will grow with it.
