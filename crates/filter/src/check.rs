//! Name resolution, type checking and lowering of the syntax tree to the IR.

use alloc::boxed::Box;
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use crate::ast::{self, ArithOp, Expr, MacroBody, Operand, Quant, RelOp, Rhs};
use crate::error::{Diagnostic, Result, Span};
use crate::fields::{self, Consts, Field, Origin, Ty};
use crate::ir::{self, CmpOp, Lit, SetItem, Test, Value};
use crate::{labels, lit, regex, value};

/// The type (and symbolic names) that the other side of a relation expects.
#[derive(Clone, Copy)]
struct Ctx {
    ty: Ty,
    /// Avulse's symbolic constants (`syn`, `echo-request`).
    consts: Consts,
    /// The field compared with, whose Wireshark labels also name values (`"TCP"`).
    field: Option<Field>,
}

/// The context of an arithmetic operand.
const INT: Ctx = Ctx {
    ty: Ty::Int,
    consts: &[],
    field: None,
};

struct Typed {
    value: Value,
    ty: Ty,
    consts: Consts,
}

impl Typed {
    fn ctx(&self) -> Ctx {
        Ctx {
            ty: self.ty,
            consts: self.consts,
            field: match self.value {
                Value::Field(f) | Value::Layer(f, _) => Some(f),
                _ => None,
            },
        }
    }
}

enum Resolved<'a> {
    Typed(Typed),
    /// A literal whose type depends on the other operand.
    Literal(&'a Operand),
}

/// Deepest chain of macros using macros. With the parser's `MAX_DEPTH`, it bounds the depth of
/// the IR, which every later pass recurses over.
const MACRO_DEPTH: usize = 4;

pub(crate) struct Checker<'a> {
    lets: &'a [ast::Let],
    stack: Vec<&'a str>,
    used: Vec<&'a str>,
    pub warnings: Vec<Diagnostic>,
    /// The compiled patterns of `matches`, in the order of their `index`.
    pub regexes: Vec<regex::Regex>,
}

impl<'a> Checker<'a> {
    pub fn new(lets: &'a [ast::Let]) -> Self {
        Checker {
            lets,
            stack: Vec::new(),
            used: Vec::new(),
            warnings: Vec::new(),
            regexes: Vec::new(),
        }
    }

    pub fn program(&mut self, p: &'a ast::Program) -> Result<Test> {
        for (i, l) in p.lets.iter().enumerate() {
            if p.lets[..i].iter().any(|o| o.name == l.name) {
                return Err(Diagnostic::error(
                    l.span,
                    format!("`{}` is defined twice", l.name),
                ));
            }
            if fields::lookup(&l.name).is_some() {
                return Err(Diagnostic::error(
                    l.span,
                    format!("`{}` is a field name", l.name),
                ));
            }
        }
        let t = self.test(&p.expr)?;
        for l in &p.lets {
            if !self.used.contains(&l.name.as_str()) {
                self.warnings.push(Diagnostic::warning(
                    l.span,
                    format!("`{}` is never used", l.name),
                ));
            }
        }
        Ok(t)
    }

    fn with_macro<T>(
        &mut self,
        name: &str,
        span: Span,
        f: impl FnOnce(&mut Self, &'a MacroBody) -> Result<T>,
    ) -> Result<T> {
        let lets = self.lets;
        let Some(l) = lets.iter().find(|l| l.name == name) else {
            return Err(Diagnostic::error(span, format!("unknown macro `${name}`"))
                .help(format!("define it first: `let {name} = ...`")));
        };
        if self.stack.contains(&l.name.as_str()) {
            return Err(Diagnostic::error(
                span,
                format!("`${name}` refers to itself"),
            ));
        }
        // Each expansion can add a whole expression's depth to the tree.
        if self.stack.len() >= MACRO_DEPTH {
            return Err(
                Diagnostic::error(span, "macros nest too deeply").help(format!(
                    "a macro can use macros at most {MACRO_DEPTH} levels deep"
                )),
            );
        }
        self.stack.push(&l.name);
        if !self.used.contains(&l.name.as_str()) {
            self.used.push(&l.name);
        }
        let r = f(self, &l.body);
        self.stack.pop();
        r
    }

    fn test(&mut self, e: &'a Expr) -> Result<Test> {
        Ok(match e {
            Expr::Or(v) => Test::Or(v.iter().map(|e| self.test(e)).collect::<Result<_>>()?),
            Expr::And(v) => Test::And(v.iter().map(|e| self.test(e)).collect::<Result<_>>()?),
            Expr::Xor(a, b) => Test::Xor(Box::new(self.test(a)?), Box::new(self.test(b)?)),
            Expr::Not(e, _) => Test::Not(Box::new(self.test(e)?)),
            Expr::Rel {
                quant,
                lhs,
                op,
                rhs,
                span,
            } => self.relation(*quant, lhs, *op, rhs, *span)?,
            Expr::Test(o) => self.bare(o)?,
        })
    }

    /// An operand used as a test.
    fn bare(&mut self, o: &'a Operand) -> Result<Test> {
        match o {
            Operand::Word(w, span) => {
                let (name, forced) = field_name(w);
                if let Some(d) = fields::lookup(name) {
                    if d.origin == Origin::Flag {
                        return Ok(Test::Truthy(Value::Field(d.field)));
                    }
                    if d.ty == Ty::Bool {
                        self.warnings.push(
                            Diagnostic::warning(
                                *span,
                                format!(
                                    "`{w}` is true whenever the field is present, even when it is 0"
                                ),
                            )
                            .help(format!("to test the flag, write `{w} == 1`")),
                        );
                    }
                    return Ok(Test::Exists(Value::Field(d.field)));
                }
                match lit::parse_bool(w) {
                    _ if forced => Err(unknown_field(name, *span)),
                    Some(b) if !w.starts_with(['0', '1']) => Ok(Test::Const(b)),
                    _ if lit::looks_like_literal(w) => Err(not_a_test(o)),
                    _ => Err(unknown_field(w, *span)),
                }
            }
            Operand::Macro(name, span) => self.with_macro(name, *span, |c, body| match body {
                MacroBody::Expr(e) => c.test(e),
                MacroBody::Set(_) => Err(Diagnostic::error(
                    *span,
                    format!("`${name}` is a set, not a test"),
                )
                .help(format!("use it after `in`, e.g. `ip.addr in ${name}`"))),
            }),
            Operand::Slice(..) | Operand::Layer(..) | Operand::Raw(..) => {
                Ok(Test::Exists(self.typed(o)?.value))
            }
            // As in Wireshark, a bare `&` or arithmetic tests that some result is not zero.
            Operand::Arith(..) | Operand::Neg(..) if is_const(o) => Err(not_a_test(o)),
            Operand::BitAnd(..) | Operand::Arith(..) | Operand::Neg(..) => {
                Ok(Test::Truthy(self.typed(o)?.value))
            }
            Operand::Group(inner, _) => self.bare(inner),
            Operand::Call(..) | Operand::Str(..) | Operand::Char(..) => Err(not_a_test(o)),
        }
    }

    fn typed(&mut self, o: &'a Operand) -> Result<Typed> {
        match self.resolve(o, None)? {
            Resolved::Typed(t) => Ok(t),
            Resolved::Literal(o) => Err(Diagnostic::error(
                o.span(),
                format!("`{o}` is a value; expected a field here"),
            )),
        }
    }

    fn resolve(&mut self, o: &'a Operand, ctx: Option<Ctx>) -> Result<Resolved<'a>> {
        let typed = |value, ty, consts| Ok(Resolved::Typed(Typed { value, ty, consts }));
        match o {
            Operand::Word(w, span) => {
                let (name, forced) = field_name(w);
                if !forced
                    && let Some(ctx) = ctx
                    && matches!(ctx.ty, Ty::Uint(_))
                    && let Some(v) = named(ctx, w, *span)?
                {
                    return typed(Value::Lit(Lit::Uint(v)), ctx.ty, &[]);
                }
                if let Some(d) = fields::lookup(name) {
                    return typed(Value::Field(d.field), d.ty, d.consts);
                }
                if forced {
                    return Err(unknown_field(name, *span));
                }
                match ctx {
                    Some(ctx) => {
                        let lit = self.literal(o, ctx)?;
                        typed(Value::Lit(lit), ctx.ty, &[])
                    }
                    None if lit::looks_like_literal(w) => Ok(Resolved::Literal(o)),
                    None => Err(unknown_field(w, *span)),
                }
            }
            Operand::Str(..) | Operand::Char(..) => match ctx {
                Some(ctx) => {
                    let lit = self.literal(o, ctx)?;
                    typed(Value::Lit(lit), ctx.ty, &[])
                }
                None => Ok(Resolved::Literal(o)),
            },
            Operand::Macro(name, span) => self.with_macro(name, *span, |c, body| match body {
                MacroBody::Expr(Expr::Test(inner)) => c.resolve(inner, ctx),
                MacroBody::Expr(_) => Err(Diagnostic::error(
                    *span,
                    format!("`${name}` is a test, not a value"),
                )),
                MacroBody::Set(_) => Err(Diagnostic::error(*span, format!("`${name}` is a set"))
                    .help(format!("use it after `in`, e.g. `ip.addr in ${name}`"))),
            }),
            Operand::Slice(base, s, _) => {
                let b = self.typed(base)?;
                if !b.ty.is_bytes() {
                    return Err(Diagnostic::error(
                        base.span(),
                        format!("cannot slice `{base}`: it is {}", b.ty),
                    )
                    .help("slices apply to protocols, addresses and byte strings"));
                }
                let value = Value::Slice(Box::new(b.value), s.clone());
                // Several ranges are copied into a bounded buffer; reject what may not fit.
                if s.len() > 1 && !fits_owned(&value) {
                    return Err(Diagnostic::error(
                        o.span(),
                        format!(
                            "these ranges can add up to more than {} bytes",
                            value::OWNED
                        ),
                    )
                    .help("give each range a length, e.g. `[0:4,8:4]`, or use one range"));
                }
                typed(value, Ty::Bytes, &[])
            }
            Operand::Group(inner, _) => self.resolve(inner, ctx),
            Operand::Raw(inner, _) => {
                let (word, layers) = match inner.as_ref() {
                    Operand::Layer(base, layers, _) => (base.as_ref(), Some(layers.clone())),
                    other => (other, None),
                };
                let Operand::Word(w, span) = word else {
                    return Err(Diagnostic::error(word.span(), "`@` applies to a field"));
                };
                let name = field_name(w).0;
                let d = fields::lookup(name).ok_or_else(|| unknown_field(name, *span))?;
                if d.origin != Origin::Wireshark || d.field == Field::FrameInterfaceName {
                    return Err(Diagnostic::error(
                        *span,
                        format!("`{name}` has no bytes in the packet"),
                    )
                    .help("`@` gives the bytes of a protocol field"));
                }
                typed(Value::Raw(d.field, layers), Ty::Bytes, &[])
            }
            Operand::Layer(base, layers, _) => {
                let d = match base.as_ref() {
                    Operand::Word(w, span) => {
                        let name = field_name(w).0;
                        fields::lookup(name).ok_or_else(|| unknown_field(name, *span))?
                    }
                    _ => {
                        return Err(Diagnostic::error(
                            base.span(),
                            "the layer operator `#` applies to a field or a protocol",
                        ));
                    }
                };
                if d.origin != Origin::Wireshark {
                    return Err(Diagnostic::error(
                        base.span(),
                        format!("`{}` is not part of a protocol layer", d.name),
                    ));
                }
                typed(Value::Layer(d.field, layers.clone()), d.ty, d.consts)
            }
            Operand::Arith(..) | Operand::Neg(..) if is_const(o) => match ctx {
                Some(ctx) => typed(Value::Lit(self.literal(o, ctx)?), ctx.ty, &[]),
                None => Ok(Resolved::Literal(o)),
            },
            Operand::Arith(op, a, b, _) => {
                let a = self.numeric(a, "arithmetic")?;
                let b = self.numeric(b, "arithmetic")?;
                let value = Value::Arith(*op, Box::new(a), Box::new(b));
                check_occurrences(&value, o)?;
                typed(value, Ty::Int, &[])
            }
            Operand::Neg(a, _) => {
                let a = self.numeric(a, "`-`")?;
                typed(Value::Neg(Box::new(a)), Ty::Int, &[])
            }
            Operand::BitAnd(a, b, _) => {
                // `&` commutes, so a literal on the left takes the type of the right side.
                // Resolve each side once: a left-nested chain would otherwise be exponential.
                let (a, b, a_t) = match self.resolve(a, None)? {
                    Resolved::Typed(t) => (a, b, t),
                    Resolved::Literal(_) => (b, a, self.typed(b)?),
                };
                let bytes = |ty| matches!(ty, Ty::Bytes | Ty::Ether | Ty::Ipv4 | Ty::Ipv6);
                let ty = match a_t.ty {
                    Ty::Uint(_) | Ty::Int => None,
                    ty if bytes(ty) => Some(ty),
                    Ty::Proto => {
                        return Err(Diagnostic::error(
                            a.span(),
                            format!("`{a}` is a protocol, which `&` cannot take"),
                        )
                        .help(format!("slice it first, e.g. `{a}[0:2] & 00:ff`")));
                    }
                    ty => {
                        return Err(Diagnostic::error(
                            a.span(),
                            format!("`&` needs integers or bytes, but `{a}` is {ty}"),
                        ));
                    }
                };
                let b_t = expect_typed(self.resolve(b, Some(a_t.ctx()))?)?;
                let fits = match ty {
                    None => matches!(b_t.ty, Ty::Uint(_) | Ty::Int),
                    Some(_) => bytes(b_t.ty),
                };
                if !fits {
                    return Err(Diagnostic::error(
                        b.span(),
                        format!("cannot combine {} and {} with `&`", a_t.ty, b_t.ty),
                    ));
                }
                let value = Value::BitAnd(Box::new(a_t.value), Box::new(b_t.value));
                check_occurrences(&value, o)?;
                if ty.is_some() && !fits_owned(&value) {
                    return Err(Diagnostic::error(
                        o.span(),
                        format!(
                            "`&` on bytes gives at most {} bytes, and `{o}` can be longer",
                            value::OWNED
                        ),
                    )
                    .help("slice a side first, e.g. `tcp.payload[0:4] & ff:ff:00:00`"));
                }
                match ty {
                    // Integers keep their constants: `tcp.flags & syn == syn`.
                    None => typed(value, a_t.ty, a_t.consts),
                    // Bytes keep the type only when both sides share it: `ip.src & 255.0.0.0`.
                    Some(ty) if ty == b_t.ty => typed(value, ty, &[]),
                    Some(_) => typed(value, Ty::Bytes, &[]),
                }
            }
            Operand::Call(name, args, span) => {
                if let "max" | "min" = name.as_str() {
                    if args.is_empty() || args.iter().all(is_const) {
                        return Err(Diagnostic::error(
                            *span,
                            format!("`{name}` needs a field among its arguments"),
                        ));
                    }
                    let args = args
                        .iter()
                        .map(|a| self.numeric(a, &format!("`{name}`")))
                        .collect::<Result<Vec<_>>>()?;
                    let max = name == "max";
                    return typed(Value::Extreme { max, args }, Ty::Int, &[]);
                }
                let [arg] = args.as_slice() else {
                    return Err(Diagnostic::error(
                        *span,
                        format!("`{name}` takes one argument"),
                    ));
                };
                match name.as_str() {
                    "upper" | "lower" => {
                        let t = self.typed(arg)?;
                        if t.ty != Ty::Str {
                            return Err(Diagnostic::error(
                                arg.span(),
                                format!("`{name}` takes a string field, but `{arg}` is {}", t.ty),
                            )
                            .help("the string fields are `iface`, `frame.interface_name` and `process.name`"));
                        }
                        let upper = name == "upper";
                        typed(
                            Value::Case {
                                upper,
                                value: Box::new(t.value),
                            },
                            Ty::Str,
                            &[],
                        )
                    }
                    "abs" => {
                        let v = self.numeric(arg, "`abs`")?;
                        typed(Value::Abs(Box::new(v)), Ty::Int, &[])
                    }
                    "len" => {
                        let t = self.typed(arg)?;
                        if !t.ty.is_bytes() {
                            return Err(Diagnostic::error(
                                arg.span(),
                                format!("`len` needs bytes, but `{arg}` is {}", t.ty),
                            ));
                        }
                        typed(Value::Len(Box::new(t.value)), Ty::Uint(32), &[])
                    }
                    "count" => {
                        let t = self.typed(arg)?;
                        if !matches!(t.value, Value::Field(_) | Value::Layer(..) | Value::Raw(..)) {
                            return Err(Diagnostic::error(
                                arg.span(),
                                "`count` takes a field name",
                            ));
                        }
                        typed(Value::Count(Box::new(t.value)), Ty::Uint(32), &[])
                    }
                    _ => Err(Diagnostic::error(
                        *span,
                        format!("the function `{name}` is not supported"),
                    )
                    .help(
                        "supported functions: `len`, `count`, `max`, `min`, `abs`, `upper`, `lower`",
                    )),
                }
            }
        }
    }

    /// An operand of arithmetic: an integer field, function or expression, or an integer.
    fn numeric(&mut self, o: &'a Operand, what: &str) -> Result<Value> {
        let t = expect_typed(self.resolve(o, Some(INT))?)?;
        match t.ty {
            Ty::Uint(_) | Ty::Int => Ok(t.value),
            ty => Err(Diagnostic::error(
                o.span(),
                format!("{what} needs integers, but `{o}` is {ty}"),
            )),
        }
    }

    /// Converts a literal to the type expected by the other operand.
    fn literal(&mut self, o: &Operand, ctx: Ctx) -> Result<Lit> {
        let span = o.span();
        if matches!(
            o,
            Operand::Arith(..) | Operand::Neg(..) | Operand::Group(..)
        ) {
            let v = const_int(o)?;
            return match ctx.ty {
                Ty::Int => Ok(Lit::Int(v)),
                Ty::Uint(bits) => Ok(match u64::try_from(v) {
                    Ok(u) => Lit::Uint(fits(u, bits, span)?),
                    // Wireshark accepts a negative value, which no field equals.
                    Err(_) => Lit::Int(v),
                }),
                Ty::Bytes => u8::try_from(v).map(|b| Lit::Bytes(vec![b])).map_err(|_| {
                    Diagnostic::error(span, format!("{v} is too large for a byte value"))
                }),
                ty => Err(Diagnostic::error(
                    span,
                    format!("expected {ty}, found the integer {v}"),
                )),
            };
        }
        let mismatch = || {
            let mut d = Diagnostic::error(span, format!("expected {}, found `{o}`", ctx.ty));
            let labels = ctx.field.map_or(&[][..], labels::labels);
            let names: Vec<&str> = ctx
                .consts
                .iter()
                .chain(labels)
                .map(|(n, _)| *n)
                .take(8)
                .collect();
            if !names.is_empty() {
                d = d.help(format!("known names: {}", names.join(", ")));
            }
            d
        };
        let lit = match (o, ctx.ty) {
            (Operand::Word(w, _), Ty::Uint(_))
                if w.starts_with('-') && lit::parse_int(w).is_some() =>
            {
                Lit::Int(lit::parse_int(w).unwrap_or_default())
            }
            (Operand::Word(w, _), Ty::Int) => match lit::parse_int(w) {
                Some(v) => Lit::Int(v),
                None if looks_like_field(w) => return Err(unknown_field(w, span)),
                None => return Err(mismatch()),
            },
            (Operand::Char(c, _), Ty::Int) => Lit::Int(*c as i64),
            (Operand::Word(w, _), Ty::Uint(bits)) => {
                let v = named(ctx, w, span)?
                    .or_else(|| lit::parse_uint(w))
                    .ok_or_else(|| {
                        if looks_like_field(w) {
                            unknown_field(w, span)
                        } else {
                            mismatch()
                        }
                    })?;
                Lit::Uint(fits(v, bits, span)?)
            }
            (Operand::Char(c, _), Ty::Uint(bits)) => Lit::Uint(fits(*c as u64, bits, span)?),
            // Labels such as `"Set"`, quoted or not, as in Wireshark.
            (Operand::Str(s, _), Ty::Uint(_) | Ty::Bool)
                if !ctx.consts.is_empty()
                    || ctx.field.is_some_and(|f| !labels::labels(f).is_empty()) =>
            {
                let w = core::str::from_utf8(s).unwrap_or_default();
                let v = named(ctx, w, span)?.ok_or_else(|| {
                    let mut d = mismatch();
                    d.message = format!(
                        "`\"{w}\"` is not a name of a value of `{}`",
                        ctx.field.map_or("", |f| fields::def(f).name)
                    );
                    d
                })?;
                match ctx.ty {
                    Ty::Bool => Lit::Bool(v != 0),
                    _ => Lit::Uint(v),
                }
            }
            (Operand::Word(w, _), Ty::Bool) => match lit::parse_bool(w) {
                Some(b) => Lit::Bool(b),
                None => match named(ctx, w, span)? {
                    Some(v) => Lit::Bool(v != 0),
                    None => {
                        return Err(Diagnostic::error(
                            span,
                            format!("expected a boolean, found `{w}`"),
                        )
                        .help("booleans are 1, 0, true or false"));
                    }
                },
            },
            (Operand::Word(w, _), Ty::Ipv4) => match lit::parse_ipv4(w) {
                Some((a, p)) => Lit::Ipv4(a, p),
                None if lit::parse_ipv6(w).is_some() => {
                    return Err(Diagnostic::error(span, format!("`{w}` is an IPv6 address"))
                        .help("IPv6 fields are `ipv6.src`, `ipv6.dst`, `ipv6.addr`"));
                }
                None if looks_like_field(w) => return Err(unknown_field(w, span)),
                None => {
                    return Err(mismatch().help("host names are not resolved; write the address"));
                }
            },
            (Operand::Word(w, _), Ty::Ipv6) => match lit::parse_ipv6(w) {
                Some((a, p)) => Lit::Ipv6(a, p),
                None if lit::parse_ipv4(w).is_some() => {
                    return Err(Diagnostic::error(span, format!("`{w}` is an IPv4 address"))
                        .help("IPv4 fields are `ip.src`, `ip.dst`, `ip.addr`; IPv4-mapped addresses are `::ffff:a.b.c.d`"));
                }
                None if looks_like_field(w) => return Err(unknown_field(w, span)),
                None => {
                    return Err(mismatch().help("host names are not resolved; write the address"));
                }
            },
            (Operand::Word(w, _), Ty::Ip) => match (lit::parse_ipv4(w), lit::parse_ipv6(w)) {
                (Some((a, p)), _) => Lit::Ipv4(a, p),
                (None, Some((a, p))) => Lit::Ipv6(a, p),
                _ if looks_like_field(w) => return Err(unknown_field(w, span)),
                _ => return Err(mismatch()),
            },
            (Operand::Word(w, _), Ty::Ether) => match lit::parse_mac(w) {
                Some(m) => Lit::Ether(m),
                None if looks_like_field(w) => return Err(unknown_field(w, span)),
                None => return Err(mismatch().help("MAC addresses look like 00:11:22:33:44:55")),
            },
            // As in Wireshark, an integer is one byte: `tcp[13] == 18` is 0x12, `tcp[13] == 18:`
            // is 0x18.
            (Operand::Word(w, _), Ty::Proto) if lit::parse_uint(w).is_some() => {
                return Err(Diagnostic::error(
                    span,
                    format!("the integer `{w}` cannot be compared with a protocol"),
                )
                .help(format!(
                    "write a byte string such as `{w}:` or a quoted string"
                )));
            }
            (Operand::Word(w, _), Ty::Bytes) if lit::parse_uint(w).is_some() => {
                match lit::parse_uint(w).and_then(|v| u8::try_from(v).ok()) {
                    Some(b) => {
                        // Only where the hex reading differs: `18`, not `9` or `02`.
                        if w.len() <= 2 && u8::from_str_radix(w, 16).ok() != Some(b) {
                            self.warnings.push(
                                Diagnostic::warning(
                                    span,
                                    format!(
                                        "`{w}` is the integer {b} (0x{b:02x}), as in Wireshark 4.6"
                                    ),
                                )
                                .help(format!(
                                    "older Wireshark versions read it as the byte 0x{w}; write \
                                     `0x{b:02x}` or `{w}:` to make the intent explicit"
                                )),
                            );
                        }
                        Lit::Bytes(vec![b])
                    }
                    None => {
                        return Err(Diagnostic::error(
                            span,
                            format!("`{w}` is too large for a byte value"),
                        )
                        .help("write a byte string such as `11:40`, or slice one byte"));
                    }
                }
            }
            (Operand::Word(w, _), Ty::Bytes | Ty::Proto) => match lit::parse_bytes(w) {
                Some(b) => Lit::Bytes(b),
                None if looks_like_field(w) => return Err(unknown_field(w, span)),
                None => return Err(mismatch().help("byte strings look like 47:45:54 or \"GET\"")),
            },
            (Operand::Word(w, _), Ty::Str) => Lit::Bytes(w.as_bytes().to_vec()),
            (Operand::Str(s, _), Ty::Bytes | Ty::Proto | Ty::Str) => Lit::Bytes(s.clone()),
            (Operand::Char(c, _), Ty::Bytes | Ty::Proto | Ty::Str) => Lit::Bytes(vec![*c]),
            _ => return Err(mismatch()),
        };
        Ok(lit)
    }

    fn relation(
        &mut self,
        quant: Option<Quant>,
        lhs: &'a Operand,
        op: RelOp,
        rhs: &'a Rhs,
        span: Span,
    ) -> Result<Test> {
        match (op, rhs) {
            (RelOp::Matches, Rhs::Operand(r)) => self.matches(quant, lhs, r),
            (RelOp::Matches, Rhs::Set(_)) => Err(Diagnostic::error(
                span,
                "`matches` takes a regular expression, not a set",
            )),
            (RelOp::In | RelOp::NotIn, Rhs::Set(set)) => {
                let l = self.typed(lhs)?;
                if l.ty == Ty::Proto {
                    return Err(proto_compare(lhs));
                }
                let set = self.set(set, &l)?;
                Ok(Test::Member {
                    lhs: l.value,
                    set,
                    quant: quant.unwrap_or(Quant::Any),
                    negate: op == RelOp::NotIn,
                })
            }
            (_, Rhs::Operand(r)) => {
                let (l, r, op) = match self.resolve(lhs, None)? {
                    Resolved::Typed(l) => {
                        let ctx = if op == RelOp::Contains {
                            contains_ctx(l.ty)
                        } else {
                            l.ctx()
                        };
                        let r = expect_typed(self.resolve(r, Some(ctx))?)?;
                        (l, r, op)
                    }
                    Resolved::Literal(_) if op == RelOp::Contains => {
                        return Err(Diagnostic::error(
                            lhs.span(),
                            "the left side of `contains` must be a field",
                        ));
                    }
                    Resolved::Literal(_) => match self.resolve(r, None)? {
                        Resolved::Typed(r_t) => {
                            let l2 = expect_typed(self.resolve(lhs, Some(r_t.ctx()))?)?;
                            (r_t, l2, mirror(op))
                        }
                        Resolved::Literal(_) => {
                            return Err(Diagnostic::error(span, "this compares two values")
                                .help("one side must be a field, e.g. `tcp.port == 80`"));
                        }
                    },
                };
                if op == RelOp::Contains {
                    if !l.ty.is_bytes() || !r.ty.is_bytes() {
                        return Err(Diagnostic::error(
                            span,
                            format!("`contains` needs bytes, but the left side is {}", l.ty),
                        ));
                    }
                    return Ok(Test::Contains {
                        lhs: l.value,
                        rhs: r.value,
                        quant: quant.unwrap_or(Quant::Any),
                    });
                }
                self.comparison(lhs, l, op, quant, r, span)
            }
            (_, Rhs::Set(_)) => Err(Diagnostic::error(span, format!("`{op}` cannot take a set"))),
        }
    }

    fn matches(&mut self, quant: Option<Quant>, lhs: &'a Operand, r: &Operand) -> Result<Test> {
        let l = self.typed(lhs)?;
        if !matches!(l.ty, Ty::Bytes | Ty::Proto | Ty::Str | Ty::Ether) {
            return Err(Diagnostic::error(
                lhs.span(),
                format!("`matches` needs bytes or a string, but `{lhs}` is {}", l.ty),
            ));
        }
        let Operand::Str(bytes, span) = r else {
            return Err(Diagnostic::error(
                r.span(),
                "`matches` takes a double-quoted regular expression",
            )
            .help("e.g. `tcp.payload matches \"^GET \"`"));
        };
        let pattern = regex::pattern(bytes);
        let re = regex::compile(&pattern).map_err(|why| {
            Diagnostic::error(*span, format!("invalid regular expression: {why}")).help(
                "patterns use Rust's regex syntax: no look-around and no backreferences, unlike \
                 Wireshark's PCRE2",
            )
        })?;
        self.regexes.push(re);
        Ok(Test::Matches {
            lhs: l.value,
            pattern,
            index: self.regexes.len() - 1,
            quant: quant.unwrap_or(Quant::Any),
        })
    }

    fn comparison(
        &mut self,
        lhs: &Operand,
        l: Typed,
        op: RelOp,
        quant: Option<Quant>,
        r: Typed,
        span: Span,
    ) -> Result<Test> {
        if l.ty == Ty::Proto || r.ty == Ty::Proto {
            return Err(proto_compare(lhs));
        }
        if !compatible(l.ty, r.ty) {
            return Err(Diagnostic::error(
                span,
                format!("cannot compare {} with {}", l.ty, r.ty),
            ));
        }
        // Each Wireshark operator is a comparison and a default quantifier.
        let (op, default) = match op {
            RelOp::Eq => (CmpOp::Eq, Quant::Any),
            RelOp::Ne => (CmpOp::Ne, Quant::All),
            RelOp::AllEq => (CmpOp::Eq, Quant::All),
            RelOp::AnyNe => (CmpOp::Ne, Quant::Any),
            RelOp::Lt => (CmpOp::Lt, Quant::Any),
            RelOp::Le => (CmpOp::Le, Quant::Any),
            RelOp::Gt => (CmpOp::Gt, Quant::Any),
            RelOp::Ge => (CmpOp::Ge, Quant::Any),
            _ => return Err(Diagnostic::error(span, format!("unexpected `{op}`"))),
        };
        let ordering = matches!(op, CmpOp::Lt | CmpOp::Le | CmpOp::Gt | CmpOp::Ge);
        if ordering && !l.ty.is_ordered() {
            return Err(
                Diagnostic::error(span, format!("{} cannot be ordered", l.ty))
                    .help("use `==` or `!=`"),
            );
        }
        let prefix = |v: &Value| matches!(v, Value::Lit(l) if l.has_prefix());
        if ordering && (prefix(&l.value) || prefix(&r.value)) {
            return Err(
                Diagnostic::error(span, "address ranges only support `==` and `!=`")
                    .help("use `in {a..b}` for an ordered range"),
            );
        }
        Ok(Test::Cmp {
            lhs: l.value,
            op,
            quant: quant.unwrap_or(default),
            rhs: r.value,
        })
    }

    fn set(&mut self, set: &'a ast::Set, l: &Typed) -> Result<Vec<SetItem>> {
        match set {
            ast::Set::Macro(name, span) => self.with_macro(name, *span, |c, body| match body {
                MacroBody::Set(s) => c.set(s, l),
                MacroBody::Expr(_) => {
                    Err(Diagnostic::error(*span, format!("`${name}` is not a set")))
                }
            }),
            ast::Set::Items(items, _) => items
                .iter()
                .map(|item| {
                    let lo = self.set_member(&item.lo, l)?;
                    let Some(hi_op) = &item.hi else {
                        return Ok(SetItem::One(lo));
                    };
                    let hi = self.set_member(hi_op, l)?;
                    let span = item.lo.span().to(hi_op.span());
                    let orderable =
                        matches!(l.ty, Ty::Uint(_) | Ty::Int | Ty::Ipv4 | Ty::Ipv6 | Ty::Ip);
                    if !orderable || lo.has_prefix() || hi.has_prefix() {
                        return Err(Diagnostic::error(
                            span,
                            format!("ranges are not supported for {}", l.ty),
                        ));
                    }
                    if !lit_le(&lo, &hi) {
                        return Err(Diagnostic::error(
                            span,
                            "the range is empty: its start is above its end",
                        ));
                    }
                    Ok(SetItem::Range(lo, hi))
                })
                .collect(),
        }
    }

    fn set_member(&mut self, o: &'a Operand, l: &Typed) -> Result<Lit> {
        match expect_typed(self.resolve(o, Some(l.ctx()))?)?.value {
            Value::Lit(lit) => Ok(lit),
            _ => Err(Diagnostic::error(
                o.span(),
                "set members must be values, not fields",
            )),
        }
    }
}

fn expect_typed(r: Resolved<'_>) -> Result<Typed> {
    match r {
        Resolved::Typed(t) => Ok(t),
        Resolved::Literal(o) => Err(Diagnostic::error(
            o.span(),
            format!("`{o}` needs a field to compare with"),
        )),
    }
}

/// A name for a value of the field the context compares with: Avulse's constants first, then
/// Wireshark's labels, case-insensitively. A label of several values is an error: Wireshark then
/// compares the displayed text, which Avulse does not do.
fn named(ctx: Ctx, w: &str, span: Span) -> Result<Option<u64>> {
    if let Some(v) = fields::constant(ctx.consts, w) {
        return Ok(Some(v));
    }
    let Some(f) = ctx.field else {
        return Ok(None);
    };
    let mut found = labels::labels(f)
        .iter()
        .filter(|(l, _)| l.eq_ignore_ascii_case(w))
        .map(|&(_, v)| v);
    let Some(first) = found.next() else {
        return Ok(None);
    };
    if found.any(|v| v != first) {
        return Err(Diagnostic::error(
            span,
            format!("`{w}` names several values of `{}`", fields::def(f).name),
        )
        .help("write the number, or a set of them with `in {…}`"));
    }
    Ok(Some(first))
}

fn contains_ctx(ty: Ty) -> Ctx {
    Ctx {
        // A protocol keeps its type so that `tcp contains 80` is rejected as in Wireshark.
        ty: match ty {
            Ty::Str | Ty::Proto => ty,
            _ => Ty::Bytes,
        },
        consts: &[],
        field: None,
    }
}

fn mirror(op: RelOp) -> RelOp {
    match op {
        RelOp::Lt => RelOp::Gt,
        RelOp::Le => RelOp::Ge,
        RelOp::Gt => RelOp::Lt,
        RelOp::Ge => RelOp::Le,
        op => op,
    }
}

fn compatible(a: Ty, b: Ty) -> bool {
    match (a, b) {
        (Ty::Uint(_) | Ty::Int, Ty::Uint(_) | Ty::Int) => true,
        (Ty::Ip, Ty::Ipv4 | Ty::Ipv6 | Ty::Ip) | (Ty::Ipv4 | Ty::Ipv6, Ty::Ip) => true,
        (Ty::Bytes | Ty::Ether | Ty::Str, Ty::Bytes | Ty::Ether | Ty::Str) => true,
        (a, b) => a == b,
    }
}

fn lit_le(a: &Lit, b: &Lit) -> bool {
    let num = |l: &Lit| match l {
        Lit::Uint(v) => Some(*v as i128),
        Lit::Int(v) => Some(*v as i128),
        _ => None,
    };
    if let (Some(a), Some(b)) = (num(a), num(b)) {
        return a <= b;
    }
    match (a, b) {
        (Lit::Ipv4(a, _), Lit::Ipv4(b, _)) => a <= b,
        (Lit::Ipv6(a, _), Lit::Ipv6(b, _)) => a <= b,
        _ => false,
    }
}

fn fits(v: u64, bits: u8, span: Span) -> Result<u64> {
    if bits >= 64 || v < 1 << bits {
        Ok(v)
    } else {
        Err(Diagnostic::error(
            span,
            format!("{v} does not fit in {bits} bits"),
        ))
    }
}

/// Whether an operand is a constant integer expression (`1 + 2`, `-0x10`, `{'a' * 2}`).
/// Most occurrences `v` can have: arithmetic and `&` combine every pair.
fn occurrences(v: &Value) -> usize {
    match v {
        Value::Field(f) | Value::Layer(f, _) | Value::Raw(f, _) => value::occurrences(*f),
        Value::Slice(v, _)
        | Value::Len(v)
        | Value::Case { value: v, .. }
        | Value::Neg(v)
        | Value::Abs(v) => occurrences(v),
        Value::BitAnd(a, b) | Value::Arith(_, a, b) => {
            occurrences(a).saturating_mul(occurrences(b))
        }
        Value::Count(_) | Value::Extreme { .. } | Value::Lit(_) => 1,
    }
}

/// Rejects a combination with more occurrences than the evaluator holds.
fn check_occurrences(v: &Value, o: &Operand) -> Result<()> {
    let n = occurrences(v);
    if n <= value::MAX {
        return Ok(());
    }
    Err(Diagnostic::error(
        o.span(),
        format!(
            "`{o}` has up to {n} combinations of occurrences, more than the {} values Avulse evaluates",
            value::MAX
        ),
    )
    .help("use fields with one occurrence, e.g. `tcp.srcport` instead of `tcp.port`"))
}

/// Whether the byte string `v` always fits the evaluator's buffer for computed bytes.
fn fits_owned(v: &Value) -> bool {
    byte_len(v).is_some_and(|n| n <= value::OWNED)
}

/// Longest byte string `v` can be, if that is bounded.
fn byte_len(v: &Value) -> Option<usize> {
    let shorter = |a: Option<usize>, b: Option<usize>| match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    match v {
        Value::Field(f) | Value::Layer(f, _) => match fields::def(*f).ty {
            Ty::Ether => Some(6),
            Ty::Ipv4 => Some(4),
            Ty::Ipv6 => Some(16),
            _ => None,
        },
        Value::Lit(Lit::Ipv4(..)) => Some(4),
        Value::Lit(Lit::Ipv6(..)) => Some(16),
        Value::Lit(Lit::Ether(_)) => Some(6),
        Value::Lit(Lit::Bytes(b)) => Some(b.len()),
        Value::Slice(base, ranges) => {
            let base = byte_len(base);
            ranges.iter().try_fold(0usize, |total, r| {
                let n = match r.end {
                    ir::SliceEnd::Len(n) => usize::try_from(n).ok(),
                    ir::SliceEnd::Inclusive(e) => e
                        .checked_sub(r.start)
                        .and_then(|d| usize::try_from(d + 1).ok()),
                    // `[-n:]` is the last `n` bytes.
                    ir::SliceEnd::Open if r.start < 0 => {
                        usize::try_from(r.start.unsigned_abs()).ok()
                    }
                    ir::SliceEnd::Open => None,
                };
                total.checked_add(shorter(n, base)?)
            })
        }
        Value::BitAnd(a, b) => shorter(byte_len(a), byte_len(b)),
        Value::Case { value, .. } => byte_len(value),
        _ => None,
    }
}

fn is_const(o: &Operand) -> bool {
    match o {
        Operand::Word(w, _) => fields::lookup(w).is_none() && lit::parse_int(w).is_some(),
        Operand::Char(..) => true,
        Operand::Group(a, _) | Operand::Neg(a, _) => is_const(a),
        Operand::Arith(_, a, b, _) => is_const(a) && is_const(b),
        _ => false,
    }
}

/// Folds a constant integer expression, as Wireshark does.
fn const_int(o: &Operand) -> Result<i64> {
    let overflow = || Diagnostic::error(o.span(), "the constant overflows a 64-bit integer");
    match o {
        Operand::Word(w, span) => lit::parse_int(w)
            .ok_or_else(|| Diagnostic::error(*span, format!("expected an integer, found `{w}`"))),
        Operand::Char(c, _) => Ok(*c as i64),
        Operand::Group(a, _) => const_int(a),
        Operand::Neg(a, _) => const_int(a)?.checked_neg().ok_or_else(overflow),
        Operand::Arith(op, a, b, span) => {
            let (a, b) = (const_int(a)?, const_int(b)?);
            if matches!(op, ArithOp::Div | ArithOp::Mod) && b == 0 {
                return Err(Diagnostic::error(*span, "division by zero"));
            }
            ir::arith(*op, a, b).ok_or_else(overflow)
        }
        _ => Err(Diagnostic::error(
            o.span(),
            format!("expected an integer, found `{o}`"),
        )),
    }
}

/// The field name a word refers to, and whether a leading `.` forces it to be a field (as in
/// Wireshark, where `.ip.src` is never read as a literal).
fn field_name(w: &str) -> (&str, bool) {
    match w.strip_prefix('.') {
        Some(name) => (name, true),
        None => (w, false),
    }
}

fn looks_like_field(w: &str) -> bool {
    w.starts_with(|c: char| c.is_ascii_alphabetic())
        && w.contains('.')
        && !lit::looks_like_literal(w)
}

fn not_a_test(o: &Operand) -> Diagnostic {
    let d = Diagnostic::error(o.span(), format!("`{o}` is a value, not a test"));
    match o {
        Operand::Call(..) => d.help(format!("compare it, e.g. `{o} > 0`")),
        _ => d.help("compare it with a field, e.g. `tcp.port == 80`"),
    }
}

fn proto_compare(o: &Operand) -> Diagnostic {
    Diagnostic::error(
        o.span(),
        format!("`{o}` is a protocol and cannot be compared"),
    )
    .help(format!(
        "compare a field or a slice instead, e.g. `{o}[0:2] == 00:50`"
    ))
}

pub(crate) fn unknown_field(w: &str, span: Span) -> Diagnostic {
    if let Some((_, why)) = fields::UNSUPPORTED
        .iter()
        .find(|(n, _)| w == *n || w.strip_prefix(n).is_some_and(|r| r.starts_with('.')))
    {
        // Name the field as written: the entry may be a prefix (`tcp.analysis` for
        // `tcp.analysis.flags`).
        return Diagnostic::error(span, format!("`{w}` is not supported")).help(*why);
    }
    let proto = w.split('.').next().unwrap_or(w);
    if fields::APPLICATION.contains(&proto) && fields::lookup(proto).is_none() {
        return Diagnostic::error(span, format!("Avulse does not decode `{proto}`")).help(
            "filters see headers up to the transport layer; match ports or payload bytes instead, \
             e.g. `tcp.port == 443` or `tcp.payload contains \"...\"`",
        );
    }
    let d = Diagnostic::error(span, format!("unknown field `{w}`"));
    // `tcp.port-1`: `-` and `/` belong to words, so arithmetic needs spaces, as in Wireshark.
    if let Some((i, sep)) = w.char_indices().rev().find(|(_, c)| matches!(c, '-' | '/'))
        && fields::lookup(&w[..i]).is_some()
    {
        let rest = &w[i + 1..];
        return d.help(format!(
            "write `{} {sep} {rest}` with spaces for arithmetic",
            &w[..i]
        ));
    }
    match closest(w) {
        Some(s) => d.help(format!("did you mean `{s}`?")),
        None => d.help("run `avulse filter fields` for the list of fields"),
    }
}

fn closest(w: &str) -> Option<&'static str> {
    let limit = (w.len() / 4).clamp(1, 3);
    fields::FIELDS
        .iter()
        .map(|d| (distance(w, d.name), d.name))
        .filter(|(d, _)| *d <= limit)
        .min_by_key(|(d, _)| *d)
        .map(|(_, n)| n)
}

fn distance(a: &str, b: &str) -> usize {
    let b = b.as_bytes();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.bytes().enumerate() {
        let mut cur = vec![i + 1; b.len() + 1];
        for (j, &cb) in b.iter().enumerate() {
            cur[j + 1] = (prev[j] + usize::from(ca != cb))
                .min(prev[j + 1] + 1)
                .min(cur[j] + 1);
        }
        prev = cur;
    }
    prev[b.len()]
}
