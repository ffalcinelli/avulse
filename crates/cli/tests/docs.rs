//! Keeps the documentation honest: every filter in the guide and the README compiles (or fails,
//! when marked so), and the field reference matches the field registry.

use std::path::{Path, PathBuf};
use std::process::Command;

use avulse_filter::Filter;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn markdown_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "md") {
                out.push(path);
            }
        }
    }
    let mut files = vec![root().join("README.md")];
    walk(&root().join("book/src"), &mut files);
    files
}

/// A filter taken from a ```` ```filter ```` block.
struct Example {
    file: PathBuf,
    line: usize,
    src: String,
    error: bool,
}

/// The filters in the ```` ```filter ```` and ```` ```filter,error ```` blocks of `text`. A blank
/// line separates filters in a block, except after `let` lines, which belong to the next filter.
fn examples(file: &Path, text: &str) -> Vec<Example> {
    let mut out = Vec::new();
    let mut block: Option<(bool, usize, Vec<&str>)> = None;
    for (i, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        match &mut block {
            None => {
                if let Some(info) = trimmed.strip_prefix("```") {
                    let mut tags = info.split(',').map(str::trim);
                    if tags.next() == Some("filter") {
                        block = Some((tags.any(|t| t == "error"), i + 2, Vec::new()));
                    }
                }
            }
            Some((error, start, lines)) => {
                if trimmed == "```" {
                    let mut pending = String::new();
                    let mut line_no = *start;
                    for chunk in split_blank(lines) {
                        if pending.is_empty() {
                            line_no = *start + chunk.0;
                        }
                        pending += &chunk.1;
                        let last = chunk.1.lines().rev().find(|l| !is_comment(l));
                        if last.is_some_and(|l| l.trim_start().starts_with("let ")) {
                            pending.push('\n');
                            continue;
                        }
                        out.push(Example {
                            file: file.to_path_buf(),
                            line: line_no,
                            src: std::mem::take(&mut pending),
                            error: *error,
                        });
                    }
                    assert!(
                        pending.is_empty(),
                        "{}:{start}: a filter block ends with `let`",
                        file.display()
                    );
                    block = None;
                } else {
                    lines.push(line);
                }
            }
        }
    }
    assert!(block.is_none(), "{}: unclosed filter block", file.display());
    out
}

fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.is_empty() || t.starts_with("//") || (t.starts_with('#') && !t.starts_with("#["))
}

/// Splits lines into chunks separated by blank lines: (offset of the first line, text).
fn split_blank(lines: &[&str]) -> Vec<(usize, String)> {
    let mut chunks = Vec::new();
    let mut cur: Option<(usize, String)> = None;
    for (i, line) in lines.iter().enumerate() {
        if line.trim().is_empty() {
            chunks.extend(cur.take());
        } else {
            let c = cur.get_or_insert_with(|| (i, String::new()));
            c.1 += line.trim_start();
            c.1.push('\n');
        }
    }
    chunks.extend(cur);
    chunks
}

#[test]
fn filters_in_the_docs_compile() {
    let mut failures = Vec::new();
    let mut count = 0;
    for file in markdown_files() {
        let text = std::fs::read_to_string(&file).unwrap();
        for ex in examples(&file, &text) {
            count += 1;
            let file = ex.file.strip_prefix(root()).unwrap_or(&ex.file);
            let at = format!("{}:{}", file.display(), ex.line);
            match (Filter::compile(&ex.src), ex.error) {
                (Ok(_), true) => failures.push(format!("{at}: compiles, but is marked `error`")),
                (Err(e), false) => failures.push(format!("{at}:\n{}", e.render(&ex.src))),
                _ => {}
            }
        }
    }
    assert!(count > 50, "found only {count} filters in the docs");
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[test]
fn field_reference_is_up_to_date() {
    let output = Command::new(env!("CARGO_BIN_EXE_avulse"))
        .args(["filter", "fields", "--format", "markdown"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let expected = String::from_utf8(output.stdout).unwrap();
    let path = root().join("book/src/reference/fields.md");
    if std::env::var_os("AVULSE_BLESS").is_some() {
        std::fs::write(&path, &expected).unwrap();
        return;
    }
    let actual = std::fs::read_to_string(&path).unwrap_or_default();
    // Git may check the file out with CRLF line endings on Windows.
    assert!(
        actual.replace("\r\n", "\n") == expected,
        "{} is out of date: run `AVULSE_BLESS=1 cargo test -p avulse-cli --test docs`",
        path.display()
    );
}
