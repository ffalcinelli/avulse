//! Command-line tool: capture, inject and filter check/explain/fmt/convert.

use std::fmt::Write as _;
use std::io::{IsTerminal, Read, Write};
use std::process::ExitCode;

use avulse_filter::fields::{FIELDS, Origin};
use avulse_filter::{Diagnostic, Filter, Meta, parse};
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
}

#[derive(Subcommand)]
enum FilterCommand {
    /// Check a filter and print its warnings.
    Check(Source),
    /// Print a filter in canonical form.
    Fmt(Source),
    /// Print the compiled filter (typed IR).
    Explain(Source),
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
    /// List the fields filters can use.
    Fields,
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
    let Command::Filter(cmd) = cli.command;
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
        FilterCommand::Explain(src) => {
            let f = compile(&src.read()?)?;
            let mut text = format!("{}\n", f.ir());
            if f.user_space_only() {
                text += "note: `matches` runs in user space only; kernel backends pass these packets up\n";
            }
            out(&text);
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
        FilterCommand::Fields => {
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
            out(&s);
            Ok(ExitCode::SUCCESS)
        }
    }
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
