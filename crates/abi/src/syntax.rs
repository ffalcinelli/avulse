//! The language of a filter.

/// The language of a handle's filter.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum Syntax {
    /// Avulse's language, a subset of Wireshark's display filters
    /// (`avulse_filter::Filter::compile`).
    #[default]
    Native = 0,
    /// WinDivert 2.2's filter language (`avulse_filter::Filter::compile_windivert`).
    WinDivert = 1,
}

impl TryFrom<u8> for Syntax {
    type Error = u8;

    fn try_from(n: u8) -> core::result::Result<Syntax, u8> {
        match n {
            0 => Ok(Syntax::Native),
            1 => Ok(Syntax::WinDivert),
            n => Err(n),
        }
    }
}
