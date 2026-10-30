# Installing the CLI

The `avulse` command-line tool is not on crates.io yet. Build it from the repository with a
recent stable Rust toolchain (the crates use the 2024 edition):

```console
$ cargo install --locked --git https://github.com/ffalcinelli/avulse avulse-cli
$ avulse --version
```

Or clone the repository and run it in place:

```console
$ git clone https://github.com/ffalcinelli/avulse
$ cd avulse
$ cargo run -p avulse-cli -- filter check 'tcp.port == 443'
```

`avulse filter` works the same on Linux, Windows and macOS, and needs no privileges. On Linux,
`avulse cleanup` removes handles left behind by processes that exited without closing them (needs
root, or `CAP_BPF` and `CAP_NET_ADMIN`).

To try filters without installing anything, use the
[playground](https://ffalcinelli.github.io/avulse/#playground).
