//! Open flags, parameters and shutdown directions, with WinDivert's values and limits.

use core::fmt;
use core::ops::{BitOr, BitOrAssign};

/// Flags of [`Handle::open`](crate::Handle::open). The bit values are WinDivert's.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Flags(u64);

impl Flags {
    /// No flag: divert the matching packets.
    pub const NONE: Flags = Flags(0);
    /// Receive copies; the packets continue on their way.
    pub const SNIFF: Flags = Flags(0x0001);
    /// Drop the matching packets, and receive nothing.
    pub const DROP: Flags = Flags(0x0002);
    /// The handle only receives; `send` fails.
    pub const RECV_ONLY: Flags = Flags(0x0004);
    /// The handle only sends; nothing is captured.
    pub const SEND_ONLY: Flags = Flags(0x0008);
    /// Do not install the driver or programs if they are missing (fail instead).
    pub const NO_INSTALL: Flags = Flags(0x0010);
    /// Also capture IP fragments other than the first.
    pub const FRAGMENTS: Flags = Flags(0x0020);

    const ALL: u64 = 0x003f;
    const NAMES: [(Flags, &'static str); 6] = [
        (Flags::SNIFF, "SNIFF"),
        (Flags::DROP, "DROP"),
        (Flags::RECV_ONLY, "RECV_ONLY"),
        (Flags::SEND_ONLY, "SEND_ONLY"),
        (Flags::NO_INSTALL, "NO_INSTALL"),
        (Flags::FRAGMENTS, "FRAGMENTS"),
    ];

    /// The flags of a WinDivert flag word, or `None` if it has unknown bits.
    pub const fn from_bits(bits: u64) -> Option<Flags> {
        if bits & !Self::ALL == 0 {
            Some(Flags(bits))
        } else {
            None
        }
    }

    /// The flag word.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Whether every flag of `other` is set.
    pub const fn contains(self, other: Flags) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether no flag is set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl BitOr for Flags {
    type Output = Flags;

    fn bitor(self, rhs: Flags) -> Flags {
        Flags(self.0 | rhs.0)
    }
}

impl BitOrAssign for Flags {
    fn bitor_assign(&mut self, rhs: Flags) {
        self.0 |= rhs.0;
    }
}

impl fmt::Debug for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("NONE");
        }
        let mut first = true;
        for (flag, name) in Self::NAMES {
            if self.contains(flag) {
                if !first {
                    f.write_str(" | ")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        Ok(())
    }
}

/// A queue parameter of a handle ([`Handle::set_param`](crate::Handle::set_param)).
///
/// Received packets wait in a queue until `recv` takes them. Packets that arrive when the queue is
/// full, or that waited too long, are dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Param {
    /// Most packets in the queue: 32 to 16,384, default 4,096.
    QueueLength,
    /// Longest a packet may wait, in milliseconds: 100 to 16,000, default 2,000.
    QueueTime,
    /// Most bytes in the queue: 65,535 to 33,554,432, default 4,194,304.
    QueueSize,
}

impl Param {
    /// Every parameter.
    pub const ALL: [Param; 3] = [Param::QueueLength, Param::QueueTime, Param::QueueSize];

    /// The accepted values (WinDivert's).
    pub const fn range(self) -> core::ops::RangeInclusive<u64> {
        match self {
            Param::QueueLength => 32..=16_384,
            Param::QueueTime => 100..=16_000,
            Param::QueueSize => 65_535..=33_554_432,
        }
    }

    /// The value a new handle starts with.
    pub const fn default_value(self) -> u64 {
        match self {
            Param::QueueLength => 4_096,
            Param::QueueTime => 2_000,
            Param::QueueSize => 4_194_304,
        }
    }

    pub(crate) const fn index(self) -> usize {
        self as usize
    }
}

/// What [`Handle::shutdown`](crate::Handle::shutdown) stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Shutdown {
    /// Stop capturing. `recv` returns the packets already queued, then
    /// [`Error::Shutdown`](crate::Error::Shutdown).
    Recv,
    /// Stop sending: `send` fails with [`Error::Shutdown`](crate::Error::Shutdown).
    Send,
    /// Both.
    Both,
}
