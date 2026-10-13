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

The CLI works the same on Linux, Windows and macOS, and needs no privileges: today it only works
with filters. The capture and injection commands will come with the backends.

To try filters without installing anything, use the
[playground](https://ffalcinelli.github.io/avulse/#playground).
