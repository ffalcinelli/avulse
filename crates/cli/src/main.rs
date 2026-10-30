//! Command-line tool: capture, inject and filter check/explain/fmt/convert.

use std::fmt::Write as _;
use std::io::{IsTerminal, Read, Write};
use std::process::ExitCode;

use avulse_filter::fields::{APPLICATION, FIELDS, FieldDef, Origin, Ty, UNSUPPORTED};
use avulse_filter::{Diagnostic, Filter, Layer, Meta, parse};
use avulse_proto::{Link, Packet};
use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "avulse",
    version,
    about = "Divert, modify and re-inject network packets"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Work with filters.
    #[command(subcommand)]
    Filter(FilterCommand),
    /// Remove what processes that died without closing their handles left behind (on Linux, their
    /// TC filters). Needs root.
    Cleanup,
}

#[derive(Subcommand)]
enum FilterCommand {
    /// Check a filter and print its warnings.
    Check(Source),
    /// Print a filter in canonical form.
    Fmt(Source),
    /// Print the compiled filter (typed IR).
    Explain {
        #[command(flatten)]
        source: Source,
        /// Also print the bytecode that kernel backends run.
        #[arg(long)]
        bytecode: bool,
    },
    /// Evaluate a filter against one packet given in hex. Exits 0 on a match, 1 otherwise.
    Eval {
        #[command(flatten)]
        source: Source,
        /// Packet bytes in hex (spaces, colons and newlines are ignored).
        #[arg(long)]
        hex: String,
        /// What the packet starts with.
        #[arg(long, value_enum, default_value_t = LinkArg::Ethernet)]
        link: LinkArg,
        /// Treat the packet as outbound.
        #[arg(long)]
        outbound: bool,
        /// Interface name for `iface`.
        #[arg(long)]
        iface: Option<String>,
    },
    /// Convert a WinDivert filter to an Avulse filter that selects the same packets.
    Convert {
        #[command(flatten)]
        source: Source,
        /// The WinDivert layer the filter is for.
        #[arg(long, value_enum, default_value_t = LayerArg::Network)]
        layer: LayerArg,
    },
    /// List the fields filters can use.
    Fields {
        /// Output format. `markdown` is the guide's field reference.
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Markdown,
}

#[derive(Args)]
struct Source {
    /// The filter. Use `-` to read it from stdin.
    #[arg(required_unless_present = "file")]
    filter: Option<String>,
    /// Read the filter from a file.
    #[arg(short, long, conflicts_with = "filter")]
    file: Option<std::path::PathBuf>,
}

#[derive(Clone, Copy, ValueEnum)]
enum LayerArg {
    Network,
    NetworkForward,
    Flow,
    Socket,
    Reflect,
}

/// Largest converted filter, in tests: native filters have no conditional, so WinDivert's
/// `(a? b: c)` repeats `a`, and nested conditions can double the size at every level.
const CONVERT_MAX_TESTS: usize = 10_000;

#[derive(Clone, Copy, ValueEnum)]
enum LinkArg {
    Ethernet,
    Ip,
}

impl Source {
    fn read(&self) -> Result<String, String> {
        match (&self.filter, &self.file) {
            (_, Some(path)) => {
                std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
            }
            (Some(f), None) if f == "-" => {
                let mut s = String::new();
                std::io::stdin()
                    .read_to_string(&mut s)
                    .map_err(|e| e.to_string())?;
                Ok(s)
            }
            (Some(f), None) => Ok(f.clone()),
            (None, None) => Err("no filter given".into()),
        }
    }
}

/// What the Linux kernel runs of a filter, at the NETWORK layer.
fn linux_kernel(f: &Filter) -> String {
    use avulse_ebpf::codegen::{self, Env};
    let env = Env::new(Layer::Network);
    match codegen::compile(f.ir(), &env) {
        Ok(_) => "linux kernel: exact\n".into(),
        Err(codegen::Error::TooLarge) => {
            "linux kernel: every packet, and user space filters them (the filter is too large)\n"
                .into()
        }
        Err(e) => {
            let s = codegen::superset(f.ir(), &env);
            let widened = match s.test {
                avulse_filter::ir::Test::Const(true) => "every packet".to_string(),
                t => format!("the superset `{}`", t.native()),
            };
            format!("linux kernel: {widened}, and user space filters what it takes ({e})\n")
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(msg) => {
            eprint!("{msg}");
            if !msg.ends_with('\n') {
                eprintln!();
            }
            ExitCode::from(2)
        }
    }
}

fn render(d: &Diagnostic, src: &str) -> String {
    let r = d.render(src);
    if !std::io::stderr().is_terminal() {
        return r;
    }
    // Bold red/yellow level, like rustc.
    let (level, color) = match d.level {
        avulse_filter::Level::Error => ("error", "31"),
        avulse_filter::Level::Warning => ("warning", "33"),
    };
    r.replacen(
        &format!("{level}:"),
        &format!("\x1b[1;{color}m{level}\x1b[0m\x1b[1m:"),
        1,
    )
    .replacen('\n', "\x1b[0m\n", 1)
}

fn compile(src: &str) -> Result<Filter, String> {
    let f = Filter::compile(src).map_err(|e| render(&e, src))?;
    for w in f.warnings() {
        eprint!("{}", render(w, src));
    }
    Ok(f)
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    let cmd = match cli.command {
        Command::Filter(cmd) => cmd,
        Command::Cleanup => {
            let n = avulse::cleanup().map_err(|e| format!("cleanup: {e}"))?;
            out(&format!(
                "removed {n} handle{} of dead processes\n",
                if n == 1 { "" } else { "s" }
            ));
            return Ok(ExitCode::SUCCESS);
        }
    };
    match cmd {
        FilterCommand::Check(src) => {
            compile(&src.read()?)?;
            Ok(ExitCode::SUCCESS)
        }
        FilterCommand::Fmt(src) => {
            let s = src.read()?;
            out(&format!("{}\n", parse(&s).map_err(|e| render(&e, &s))?));
            Ok(ExitCode::SUCCESS)
        }
        FilterCommand::Explain { source, bytecode } => {
            let f = compile(&source.read()?)?;
            let mut text = format!("{}\n", f.ir());
            if f.user_space_only() {
                text += "note: `matches` runs in user space only; kernel backends pass these packets up\n";
            }
            text += &linux_kernel(&f);
            if bytecode {
                match f.program() {
                    Ok(p) => {
                        let size = p.to_bytes().len();
                        let _ = write!(
                            text,
                            "\nbytecode, {} instructions, {size} bytes:\n{p}",
                            p.len()
                        );
                    }
                    Err(e) => {
                        let _ = writeln!(text, "\nno bytecode: {e}");
                    }
                }
            }
            out(&text);
            Ok(ExitCode::SUCCESS)
        }
        FilterCommand::Convert { source, layer } => {
            let s = source.read()?;
            let layer = match layer {
                LayerArg::Network => Layer::Network,
                LayerArg::NetworkForward => Layer::NetworkForward,
                LayerArg::Flow => Layer::Flow,
                LayerArg::Socket => Layer::Socket,
                LayerArg::Reflect => Layer::Reflect,
            };
            let f = Filter::compile_windivert(&s, layer).map_err(|e| render(&e, &s))?;
            let n = f.ir().native_tests();
            if n > CONVERT_MAX_TESTS {
                return Err(format!(
                    "the converted filter would have {}{n} tests, more than {CONVERT_MAX_TESTS}: \
                     native filters have no conditional, so each `(a? b: c)` repeats `a`",
                    if n == usize::MAX { "at least " } else { "" },
                ));
            }
            out(&format!("{}\n", f.ir().native()));
            Ok(ExitCode::SUCCESS)
        }
        FilterCommand::Eval {
            source,
            hex,
            link,
            outbound,
            iface,
        } => {
            let f = compile(&source.read()?)?;
            let bytes = decode_hex(&hex)?;
            let link = match link {
                LinkArg::Ethernet => Link::Ethernet,
                LinkArg::Ip => Link::Ip,
            };
            let meta = Meta {
                outbound,
                iface: iface.as_deref(),
                ..Meta::default()
            };
            let matched = f.matches(&Packet::parse(&bytes, link), &meta);
            out(if matched { "match\n" } else { "no match\n" });
            Ok(if matched {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        FilterCommand::Fields { format } => {
            out(&match format {
                Format::Text => fields_text(),
                Format::Markdown => fields_markdown(),
            });
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn fields_text() -> String {
    let mut s = String::new();
    for d in FIELDS {
        let mark = if d.origin == Origin::Wireshark {
            ' '
        } else {
            '+'
        };
        let _ = writeln!(s, "{mark} {:<28} {:<22} {}", d.name, d.ty.name(), d.desc);
        if !d.consts.is_empty() {
            let names: Vec<_> = d.consts.iter().map(|(n, _)| *n).collect();
            let _ = writeln!(s, "  {:<28} {:<22} names: {}", "", "", names.join(", "));
        }
    }
    s += "\n+ Avulse extension (not a Wireshark field)\n";
    s
}

/// The field reference of the guide (`book/src/reference/fields.md`).
fn fields_markdown() -> String {
    fn row(s: &mut String, d: &FieldDef) {
        let ty = match d.ty {
            Ty::Uint(bits) => format!("unsigned integer ({bits} bits)"),
            ty => ty.name().split_once(' ').map_or("", |(_, t)| t).to_string(),
        };
        let mut desc = d.desc.replace('|', "\\|");
        if !d.consts.is_empty() {
            let names: Vec<_> = d.consts.iter().map(|(n, _)| format!("`{n}`")).collect();
            let _ = write!(desc, ". Names: {}", names.join(", "));
        }
        let _ = writeln!(s, "| `{}` | {ty} | {desc} |", d.name);
    }
    const TABLE: &str = "| Field | Type | Description |\n| --- | --- | --- |\n";

    let mut s = String::from(
        "<!-- Generated by `avulse filter fields --format markdown`; do not edit. -->\n\n\
         # Field reference\n\n\
         Every field a filter can use. A protocol name (`tcp`) tests that the header is present,\n\
         and slices as its bytes (`tcp[13]`). The symbolic names are Avulse extensions: Wireshark's\n\
         own value labels (`ip.proto == \"UDP\"`) work too.\n\n\
         ## Wireshark fields\n\n\
         They have the same name and meaning as in Wireshark.\n",
    );
    for d in FIELDS.iter().filter(|d| d.origin == Origin::Wireshark) {
        if d.ty == Ty::Proto {
            let _ = write!(s, "\n### {}\n\n{TABLE}", d.name);
        }
        row(&mut s, d);
    }
    s += "\n## Avulse extensions\n\n\
          Metadata that is not in the packet bytes. Bare, the flags (`outbound`, `loopback`, …) test\n\
          that the value is true.\n\n";
    s += TABLE;
    for d in FIELDS.iter().filter(|d| d.origin != Origin::Wireshark) {
        row(&mut s, d);
    }
    s += "\n## Rejected Wireshark fields\n\n\
          These need state across packets or name resolution, so a filter that uses them is an\n\
          error with this hint.\n\n\
          | Field | Why |\n| --- | --- |\n";
    for (name, why) in UNSUPPORTED {
        let _ = writeln!(s, "| `{name}` | {} |", why.replace('|', "\\|"));
    }
    s += "\nProtocols that Avulse does not decode are rejected too: ";
    let names: Vec<_> = APPLICATION.iter().map(|n| format!("`{n}`")).collect();
    s += &names.join(", ");
    s += ". Match their bytes instead, such as `udp.port == 53` or\n\
          `tcp.payload contains \"HTTP/1.1\"`.\n";
    s
}

/// Writes to stdout; a closed pipe (`| head`) is not an error.
fn out(s: &str) {
    let _ = std::io::stdout().lock().write_all(s.as_bytes());
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let digits: Vec<u8> = s
        .bytes()
        .filter(|c| !c.is_ascii_whitespace() && *c != b':' && *c != b'-')
        .collect();
    if !digits.len().is_multiple_of(2) {
        return Err("odd number of hex digits".into());
    }
    digits
        .chunks(2)
        .map(|p| {
            std::str::from_utf8(p)
                .ok()
                .and_then(|p| u8::from_str_radix(p, 16).ok())
                .ok_or_else(|| format!("invalid hex `{}`", String::from_utf8_lossy(p)))
        })
        .collect()
}
