# Regular expressions

`matches`, or `~`, tests a byte value or string against a regular expression:

```filter
tcp.payload matches "^(GET|POST) "

process.name ~ "^(curl|wget)$"
```

As in Wireshark:

- matching is **case-insensitive** unless the pattern says `(?-i)`;
- patterns run over **bytes**, not UTF-8 text, so `"\\x81"` matches that byte;
- a match anywhere counts: anchor with `^` and `$` to match the whole value.

The filter string is unescaped first, then the pattern. Raw strings avoid doubling backslashes:

```filter
tcp.payload matches r"^HTTP/1\.[01] \d{3}"

tcp.payload ~ "(?-i)^GET"
```

## Rust syntax, not PCRE2

Avulse uses Rust's regular-expression engine (`regex-automata`), where Wireshark uses PCRE2. The
syntax is mostly the same, but look-around and backreferences are not supported and are reported
as errors. `$` matches only at the very end, where PCRE2 also matches before a final newline:
write `\n?$` for that.

```filter,error
tcp.payload matches "(?<=a)b"
```

## Where they run

Regular expressions are the one part of the language that allocates, so they run in user space
only. Kernel backends will pass the packets that need a regular expression up to user space, and
`avulse filter explain` notes it:

```console
$ avulse filter explain 'tcp.payload matches "^GET"'
(matches tcp.payload "^GET")
note: `matches` runs in user space only; kernel backends pass these packets up
```

In the Rust crate, `matches` needs the `regex` feature of `avulse-filter`. The CLI and the
playground have it.
