//! Name resolution, type checking and lowering of the syntax tree to the IR.

use alloc::boxed::Box;
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use crate::ast::{self, Expr, MacroBody, Operand, RelOp, Rhs};
use crate::error::{Diagnostic, Result, Span};
use crate::fields::{self, Consts, Origin, Ty};
use crate::ir::{CmpOp, Lit, SetItem, Test, Value};
use crate::lit;

/// The type (and symbolic constants) that the other side of a relation expects.
#[derive(Clone, Copy)]
struct Ctx {
    ty: Ty,
    consts: Consts,
}

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
        }
    }
}

enum Resolved<'a> {
    Typed(Typed),
    /// A literal whose type depends on the other operand.
    Literal(&'a Operand),
}

pub(crate) struct Checker<'a> {
    lets: &'a [ast::Let],
    stack: Vec<&'a str>,
    used: Vec<&'a str>,
    pub warnings: Vec<Diagnostic>,
}

impl<'a> Checker<'a> {
    pub fn new(lets: &'a [ast::Let]) -> Self {
        Checker {
            lets,
            stack: Vec::new(),
            used: Vec::new(),
            warnings: Vec::new(),
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
            Expr::Rel { lhs, op, rhs, span } => self.relation(lhs, *op, rhs, *span)?,
            Expr::Test(o) => self.bare(o)?,
        })
    }

    /// An operand used as a test.
    fn bare(&mut self, o: &'a Operand) -> Result<Test> {
        match o {
            Operand::Word(w, span) => {
                if let Some(d) = fields::lookup(w) {
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
            Operand::Slice(..) => Ok(Test::Exists(self.typed(o)?.value)),
            Operand::BitAnd(..) => Ok(Test::Truthy(self.typed(o)?.value)),
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
                if let Some(ctx) = ctx
                    && matches!(ctx.ty, Ty::Uint(_))
                    && let Some(v) = fields::constant(ctx.consts, w)
                {
                    return typed(Value::Lit(Lit::Uint(v)), ctx.ty, &[]);
                }
                if let Some(d) = fields::lookup(w) {
                    return typed(Value::Field(d.field), d.ty, d.consts);
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
                typed(Value::Slice(Box::new(b.value), *s), Ty::Bytes, &[])
            }
            Operand::BitAnd(a, b, _) => {
                let a_t = self.typed(a)?;
                if !matches!(a_t.ty, Ty::Uint(_)) {
                    return Err(Diagnostic::error(a.span(), format!("`&` needs an integer, but `{a}` is {}", a_t.ty))
                        .help("slices are bytes: compare them with bytes, or use an integer field such as `tcp.flags`"));
                }
                let b_t = expect_typed(self.resolve(b, Some(a_t.ctx()))?)?;
                if !matches!(b_t.ty, Ty::Uint(_)) {
                    return Err(Diagnostic::error(
                        b.span(),
                        format!("`&` needs an integer, but `{b}` is {}", b_t.ty),
                    ));
                }
                typed(
                    Value::BitAnd(Box::new(a_t.value), Box::new(b_t.value)),
                    a_t.ty,
                    a_t.consts,
                )
            }
            Operand::Call(name, args, span) => {
                let [arg] = args.as_slice() else {
                    return Err(Diagnostic::error(
                        *span,
                        format!("`{name}` takes one argument"),
                    ));
                };
                match name.as_str() {
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
                        if !matches!(t.value, Value::Field(_)) {
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
                    .help("supported functions: `len`, `count`")),
                }
            }
        }
    }

    /// Converts a literal to the type expected by the other operand.
    fn literal(&mut self, o: &Operand, ctx: Ctx) -> Result<Lit> {
        let span = o.span();
        let mismatch = || {
            let mut d = Diagnostic::error(span, format!("expected {}, found `{o}`", ctx.ty));
            if !ctx.consts.is_empty() {
                let names: Vec<&str> = ctx.consts.iter().map(|(n, _)| *n).take(8).collect();
                d = d.help(format!("known names: {}", names.join(", ")));
            }
            d
        };
        let lit = match (o, ctx.ty) {
            (Operand::Word(w, _), Ty::Uint(bits)) => {
                let v = fields::constant(ctx.consts, w)
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
            (Operand::Word(w, _), Ty::Bool) => Lit::Bool(lit::parse_bool(w).ok_or_else(|| {
                Diagnostic::error(span, format!("expected a boolean, found `{w}`"))
                    .help("booleans are 1, 0, true or false")
            })?),
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

    fn relation(&mut self, lhs: &'a Operand, op: RelOp, rhs: &'a Rhs, span: Span) -> Result<Test> {
        match (op, rhs) {
            (RelOp::Matches, _) => Err(Diagnostic::error(
                span,
                "`matches` (regular expressions) is not supported yet",
            )
            .help("use `contains` or a payload slice")),
            (RelOp::In | RelOp::NotIn, Rhs::Set(set)) => {
                let l = self.typed(lhs)?;
                if l.ty == Ty::Proto {
                    return Err(proto_compare(lhs));
                }
                let set = self.set(set, &l)?;
                Ok(if op == RelOp::NotIn {
                    // Wireshark: the field is present and none of its values is in the set.
                    Test::And(vec![
                        Test::Exists(l.value.clone()),
                        Test::Not(Box::new(Test::In { lhs: l.value, set })),
                    ])
                } else {
                    Test::In { lhs: l.value, set }
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
                    });
                }
                self.comparison(lhs, l, op, r, span)
            }
            (_, Rhs::Set(_)) => Err(Diagnostic::error(span, format!("`{op}` cannot take a set"))),
        }
    }

    fn comparison(
        &mut self,
        lhs: &Operand,
        l: Typed,
        op: RelOp,
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
        let op = match op {
            RelOp::Eq => CmpOp::Eq,
            RelOp::Ne => CmpOp::Ne,
            RelOp::AllEq => CmpOp::AllEq,
            RelOp::AnyNe => CmpOp::AnyNe,
            RelOp::Lt => CmpOp::Lt,
            RelOp::Le => CmpOp::Le,
            RelOp::Gt => CmpOp::Gt,
            RelOp::Ge => CmpOp::Ge,
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
                    let orderable = matches!(l.ty, Ty::Uint(_) | Ty::Ipv4 | Ty::Ipv6 | Ty::Ip);
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

fn contains_ctx(ty: Ty) -> Ctx {
    Ctx {
        // A protocol keeps its type so that `tcp contains 80` is rejected as in Wireshark.
        ty: match ty {
            Ty::Str | Ty::Proto => ty,
            _ => Ty::Bytes,
        },
        consts: &[],
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
        (Ty::Uint(_), Ty::Uint(_)) => true,
        (Ty::Ip, Ty::Ipv4 | Ty::Ipv6 | Ty::Ip) | (Ty::Ipv4 | Ty::Ipv6, Ty::Ip) => true,
        (Ty::Bytes | Ty::Ether | Ty::Str, Ty::Bytes | Ty::Ether | Ty::Str) => true,
        (a, b) => a == b,
    }
}

fn lit_le(a: &Lit, b: &Lit) -> bool {
    match (a, b) {
        (Lit::Uint(a), Lit::Uint(b)) => a <= b,
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
    if let Some((name, why)) = fields::UNSUPPORTED
        .iter()
        .find(|(n, _)| w == *n || w.strip_prefix(n).is_some_and(|r| r.starts_with('.')))
    {
        return Diagnostic::error(span, format!("`{name}` is not supported")).help(*why);
    }
    let proto = w.split('.').next().unwrap_or(w);
    if fields::APPLICATION.contains(&proto) && fields::lookup(proto).is_none() {
        return Diagnostic::error(span, format!("Avulse does not decode `{proto}`")).help(
            "filters see headers up to the transport layer; match ports or payload bytes instead, \
             e.g. `tcp.port == 443` or `tcp.payload contains \"...\"`",
        );
    }
    let d = Diagnostic::error(span, format!("unknown field `{w}`"));
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
