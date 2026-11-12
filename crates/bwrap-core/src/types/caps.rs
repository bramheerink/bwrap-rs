//! Linux capabilities as a typed value plus a 64-bit set.
//!
//! bwrap keeps the requested capabilities in two 32-bit words
//! (`requested_caps[2]`) and addresses a capability by its kernel number via
//! `CAP_TO_MASK_*`. We use one `u64`, bit `n` for capability `n`.
//!
//! Name parsing mirrors `--cap-add` / `--cap-drop`, which in bwrap call
//! libcap's `cap_from_name`. We cannot link libcap (only std + nix), so the
//! names are matched here, case-insensitively, against the canonical table.

use std::fmt;

use crate::error::Error;

/// The canonical capability names, indexed by capability number.
///
/// Positions 0..=40 as of Linux 6.x (`CAP_CHOWN` .. `CAP_CHECKPOINT_RESTORE`).
// TODO: Verify against the running kernel's cap_last_cap at startup; a newer
// kernel may define further capabilities. Unknown-but-numbered caps are still
// representable in the u64 mask; only name lookup is limited to this table.
const CAP_NAMES: &[&str] = &[
    "CAP_CHOWN",              // 0
    "CAP_DAC_OVERRIDE",       // 1
    "CAP_DAC_READ_SEARCH",    // 2
    "CAP_FOWNER",             // 3
    "CAP_FSETID",             // 4
    "CAP_KILL",               // 5
    "CAP_SETGID",             // 6
    "CAP_SETUID",             // 7
    "CAP_SETPCAP",            // 8
    "CAP_LINUX_IMMUTABLE",    // 9
    "CAP_NET_BIND_SERVICE",   // 10
    "CAP_NET_BROADCAST",      // 11
    "CAP_NET_ADMIN",          // 12
    "CAP_NET_RAW",            // 13
    "CAP_IPC_LOCK",           // 14
    "CAP_IPC_OWNER",          // 15
    "CAP_SYS_MODULE",         // 16
    "CAP_SYS_RAWIO",          // 17
    "CAP_SYS_CHROOT",         // 18
    "CAP_SYS_PTRACE",         // 19
    "CAP_SYS_PACCT",          // 20
    "CAP_SYS_ADMIN",          // 21
    "CAP_SYS_BOOT",           // 22
    "CAP_SYS_NICE",           // 23
    "CAP_SYS_RESOURCE",       // 24
    "CAP_SYS_TIME",           // 25
    "CAP_SYS_TTY_CONFIG",     // 26
    "CAP_MKNOD",              // 27
    "CAP_LEASE",              // 28
    "CAP_AUDIT_WRITE",        // 29
    "CAP_AUDIT_CONTROL",      // 30
    "CAP_SETFCAP",            // 31
    "CAP_MAC_OVERRIDE",       // 32
    "CAP_MAC_ADMIN",          // 33
    "CAP_SYSLOG",             // 34
    "CAP_WAKE_ALARM",         // 35
    "CAP_BLOCK_SUSPEND",      // 36
    "CAP_AUDIT_READ",         // 37
    "CAP_PERFMON",            // 38
    "CAP_BPF",                // 39
    "CAP_CHECKPOINT_RESTORE", // 40
];

/// The highest capability number this table knows.
// The table has 41 entries, so the index fits a u8; asserted at compile time.
#[allow(clippy::cast_possible_truncation)]
pub const CAP_LAST_KNOWN: u8 = {
    assert!(
        CAP_NAMES.len() <= 64,
        "capability table must fit the 64-bit mask"
    );
    (CAP_NAMES.len() - 1) as u8
};

/// A single Linux capability, by kernel number.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Capability(u8);

impl Capability {
    /// Wrap a raw capability number (0..=63).
    ///
    /// Numbers above the known table are allowed, matching bwrap's ability to
    /// hold unknown caps in its 64-bit mask, but have no name.
    pub fn from_number(n: u8) -> Result<Self, Error> {
        if n < 64 {
            Ok(Self(n))
        } else {
            Err(Error::invalid(format!(
                "capability number {n} out of range"
            )))
        }
    }

    /// Strict capability-name lookup — a construction helper for tests.
    ///
    /// Case-insensitive, `CAP_` prefix required. Production parses `--cap-add` /
    /// `--cap-drop` through [`Capability::from_arg`], which reproduces libcap's
    /// laxity; this strict exact-match form exists only to build known
    /// capabilities in the unit and host tests. Do not use it on an argument —
    /// it does not match bubblewrap's `--cap-add` grammar.
    pub fn from_name(name: &str) -> Result<Self, Error> {
        CAP_NAMES
            .iter()
            .position(|known| known.eq_ignore_ascii_case(name))
            // Table index is < 64, so it fits a u8.
            .map(|i| Self(u8::try_from(i).unwrap_or(u8::MAX)))
            .ok_or_else(|| Error::invalid(format!("unknown cap: {name}")))
    }

    /// Parse a `--cap-add`/`--cap-drop` argument the lax way libcap's
    /// `cap_from_name` does (verified against libcap 2.78, the Fedora 45 build):
    /// - A leading digit is read as `strtoul(base 0)` and **the trailing junk
    ///   is ignored** (`"5x"` → 5, `"08"` → 0, `"0x"` → 0, `"1e1"` → 1); the
    ///   value must be `< 64`.
    /// - Otherwise the longest leading `[A-Za-z0-9_]` run is looked up as a
    ///   name, case-insensitively, ignoring the rest (`"cap_chown,foo"` →
    ///   CAP_CHOWN). A leading `+`, `-` or space yields an empty name → unknown.
    ///
    /// The error text is bwrap's `unknown cap: <arg>` (with the full argument).
    pub fn from_arg(arg: &str) -> Result<Self, Error> {
        let unknown = || Error::invalid(format!("unknown cap: {arg}"));
        if arg.as_bytes().first().is_some_and(u8::is_ascii_digit) {
            match strtoul_base0_prefix(arg) {
                n if n < 64 => Self::from_number(u8::try_from(n).unwrap_or(u8::MAX)),
                _ => Err(unknown()),
            }
        } else {
            let b = arg.as_bytes();
            let end = b
                .iter()
                .position(|&c| !(c.is_ascii_alphanumeric() || c == b'_'))
                .unwrap_or(b.len());
            let ident = &arg[..end];
            CAP_NAMES
                .iter()
                .position(|known| known.eq_ignore_ascii_case(ident))
                .map(|i| Self(u8::try_from(i).unwrap_or(u8::MAX)))
                .ok_or_else(unknown)
        }
    }

    /// The raw capability number.
    pub fn number(self) -> u8 {
        self.0
    }

    /// The capability's bit in a [`CapSet`] mask.
    fn mask(self) -> u64 {
        1u64 << self.0
    }

    /// The canonical name, if this number is in the known table.
    pub fn name(self) -> Option<&'static str> {
        CAP_NAMES.get(self.0 as usize).copied()
    }
}

impl fmt::Debug for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => f.write_str(name),
            None => write!(f, "CAP_{}", self.0),
        }
    }
}

/// `strtoul(s, 0)` reading only the leading digits valid for the detected base
/// (`0x`/`0X` hex, leading `0` octal, else decimal) and ignoring any trailing
/// junk, exactly as libcap does for a numeric capability. `s` starts with a
/// digit. Overflow saturates (the caller rejects anything `>= 64`).
fn strtoul_base0_prefix(s: &str) -> u64 {
    let b = s.as_bytes();
    let (start, radix) = if b.len() >= 2 && b[0] == b'0' && (b[1] == b'x' || b[1] == b'X') {
        (2, 16u32)
    } else if b[0] == b'0' {
        (1, 8u32) // the leading '0' is the value if no more octal digits follow
    } else {
        (0, 10u32)
    };
    let mut val: u64 = 0;
    for &c in &b[start..] {
        match (c as char).to_digit(radix) {
            Some(d) => {
                val = val
                    .saturating_mul(u64::from(radix))
                    .saturating_add(u64::from(d))
            }
            None => break,
        }
    }
    val
}

/// A set of capabilities, one bit per capability number (bwrap's two
/// `requested_caps` words joined into one `u64`).
#[derive(Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct CapSet(u64);

impl CapSet {
    /// The empty set (`--cap-drop ALL`).
    pub const EMPTY: Self = Self(0);
    /// Every bit set (`--cap-add ALL`: bwrap sets both words to 0xFFFFFFFF,
    /// i.e. all 64 bits, not clamped to cap_last_cap).
    pub const ALL: Self = Self(u64::MAX);

    /// From raw 64-bit mask.
    pub fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    /// The raw 64-bit mask.
    pub fn bits(self) -> u64 {
        self.0
    }

    /// Low and high 32-bit words, as bwrap's `requested_caps[0]`/`[1]`
    /// (test-only: nothing in production reads the split representation).
    #[cfg(test)]
    pub fn words(self) -> (u32, u32) {
        ((self.0 & 0xffff_ffff) as u32, (self.0 >> 32) as u32)
    }

    /// Add one capability.
    pub fn insert(&mut self, cap: Capability) {
        self.0 |= cap.mask();
    }

    /// Remove one capability.
    pub fn remove(&mut self, cap: Capability) {
        self.0 &= !cap.mask();
    }

    /// Whether `cap` is in the set.
    pub fn contains(self, cap: Capability) -> bool {
        self.0 & cap.mask() != 0
    }

    /// Iterate the known capabilities present in the set (0..=CAP_LAST_KNOWN).
    pub fn iter_known(self) -> impl Iterator<Item = Capability> {
        (0..=CAP_LAST_KNOWN)
            .map(Capability)
            .filter(move |c| self.contains(*c))
    }
}

impl fmt::Debug for CapSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter_known()).finish()
    }
}

/// A single `--cap-add` / `--cap-drop` operation, in command-line order.
///
/// bwrap folds these onto `requested_caps`, which `acquire_privs()` seeds
/// before parsing (all current effective caps when root, otherwise empty).
/// Because that base is only known at runtime, the parser records the
/// operations and [`fold`](CapOp::fold) applies them later, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapOp {
    /// `--cap-add ALL`
    AddAll,
    /// `--cap-drop ALL`
    DropAll,
    /// `--cap-add CAP`
    Add(Capability),
    /// `--cap-drop CAP`
    Drop(Capability),
}

impl CapOp {
    /// Apply a sequence of operations to a base set, in order.
    pub fn fold(base: CapSet, ops: &[CapOp]) -> CapSet {
        let mut set = base;
        for op in ops {
            match *op {
                CapOp::AddAll => set = CapSet::ALL,
                CapOp::DropAll => set = CapSet::EMPTY,
                CapOp::Add(c) => set.insert(c),
                CapOp::Drop(c) => set.remove(c),
            }
        }
        set
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_ops_fold_in_order() {
        let admin = Capability::from_name("CAP_SYS_ADMIN").unwrap();
        let net = Capability::from_name("CAP_NET_ADMIN").unwrap();
        // drop ALL, then add two: only those two remain.
        let s = CapOp::fold(
            CapSet::ALL,
            &[CapOp::DropAll, CapOp::Add(admin), CapOp::Add(net)],
        );
        assert!(s.contains(admin) && s.contains(net));
        assert!(!s.contains(Capability::from_number(0).unwrap()));
        // add ALL overrides a prior drop.
        let s = CapOp::fold(CapSet::EMPTY, &[CapOp::Drop(admin), CapOp::AddAll]);
        assert_eq!(s, CapSet::ALL);
    }

    #[test]
    fn name_lookup_is_case_insensitive() {
        assert_eq!(Capability::from_name("CAP_SYS_ADMIN").unwrap().number(), 21);
        assert_eq!(Capability::from_name("cap_sys_admin").unwrap().number(), 21);
        assert_eq!(Capability::from_name("CAP_CHOWN").unwrap().number(), 0);
        assert_eq!(
            Capability::from_name("CAP_CHECKPOINT_RESTORE")
                .unwrap()
                .number(),
            40
        );
    }

    #[test]
    fn unknown_name_matches_upstream_text() {
        let e = Capability::from_name("CAP_BOGUS").unwrap_err();
        assert_eq!(e.to_string(), "unknown cap: CAP_BOGUS");
    }

    #[test]
    fn from_arg_matches_libcap_laxity() {
        // Digit-led: strtoul base 0, trailing junk ignored (libcap 2.78).
        for (arg, num) in [
            ("21", 21),
            ("0x5", 5),
            ("05", 5),
            ("5x", 5),
            ("5,6", 5),
            ("1e1", 1),
        ] {
            assert_eq!(
                Capability::from_arg(arg).unwrap().number(),
                num,
                "arg {arg}"
            );
        }
        // "08": octal stops at '8' -> 0; "0x": no hex digit -> 0.
        assert_eq!(Capability::from_arg("08").unwrap().number(), 0);
        assert_eq!(Capability::from_arg("0x").unwrap().number(), 0);
        // Names: longest identifier prefix, rest ignored.
        assert_eq!(Capability::from_arg("cap_chown,foo").unwrap().number(), 0);
        assert_eq!(
            Capability::from_arg("cap_sys_admin x").unwrap().number(),
            21
        );
        // Rejected: >= 64, unknown name, bad prefix char, bare name.
        for bad in ["64", "CAP_CHOWNX", "+5", " 5", "sys_admin"] {
            let e = Capability::from_arg(bad).unwrap_err();
            assert_eq!(e.to_string(), format!("unknown cap: {bad}"), "arg {bad}");
        }
    }

    #[test]
    fn mask_words_match_cap_to_mask() {
        // CAP_TO_MASK_0: cap 21 -> bit 21 in word 0.
        let mut s = CapSet::EMPTY;
        s.insert(Capability::from_number(21).unwrap());
        assert_eq!(s.words(), (1 << 21, 0));
        // CAP_TO_MASK_1: cap 34 -> bit (34-32)=2 in word 1.
        let mut s = CapSet::EMPTY;
        s.insert(Capability::from_number(34).unwrap());
        assert_eq!(s.words(), (0, 1 << 2));
    }

    #[test]
    fn all_is_every_bit() {
        assert_eq!(CapSet::ALL.words(), (0xFFFF_FFFF, 0xFFFF_FFFF));
        assert!(CapSet::ALL.contains(Capability::from_number(40).unwrap()));
    }

    #[test]
    fn insert_remove_contains() {
        let cap = Capability::from_name("CAP_NET_ADMIN").unwrap();
        let mut s = CapSet::EMPTY;
        assert!(!s.contains(cap));
        s.insert(cap);
        assert!(s.contains(cap));
        s.remove(cap);
        assert!(!s.contains(cap));
    }

    #[test]
    fn iter_known_stops_at_table_end() {
        // ALL has all 64 bits, but iter_known only yields 0..=40.
        assert_eq!(
            CapSet::ALL.iter_known().count(),
            usize::from(CAP_LAST_KNOWN) + 1
        );
    }

    #[test]
    fn from_number_bounds() {
        assert_eq!(Capability::from_number(0).unwrap().number(), 0);
        assert_eq!(Capability::from_number(63).unwrap().number(), 63);
        let e = Capability::from_number(64).unwrap_err();
        assert_eq!(e.to_string(), "capability number 64 out of range");
    }

    #[test]
    fn names_and_debug_output() {
        let chown = Capability::from_number(0).unwrap();
        assert_eq!(chown.name(), Some("CAP_CHOWN"));
        assert_eq!(format!("{chown:?}"), "CAP_CHOWN");
        let last = Capability::from_number(CAP_LAST_KNOWN).unwrap();
        assert_eq!(last.name(), Some("CAP_CHECKPOINT_RESTORE"));
        // Beyond the table: no name, numeric Debug.
        let unknown = Capability::from_number(60).unwrap();
        assert_eq!(unknown.name(), None);
        assert_eq!(format!("{unknown:?}"), "CAP_60");
        // Name round trip for every known cap.
        for n in 0..=CAP_LAST_KNOWN {
            let c = Capability::from_number(n).unwrap();
            assert_eq!(Capability::from_name(c.name().unwrap()).unwrap(), c);
        }
    }

    #[test]
    fn capset_words_split_low_and_high() {
        let mut s = CapSet::EMPTY;
        s.insert(Capability::from_number(0).unwrap());
        s.insert(Capability::from_number(40).unwrap());
        assert_eq!(s.words(), (1, 1 << 8));
        assert_eq!(CapSet::from_bits(s.bits()), s);
        s.remove(Capability::from_number(0).unwrap());
        assert_eq!(s.words(), (0, 1 << 8));
        assert_eq!(CapSet::ALL.words(), (u32::MAX, u32::MAX));
    }

    #[test]
    fn capset_debug_lists_known_names_only() {
        let mut s = CapSet::EMPTY;
        s.insert(Capability::from_name("cap_net_raw").unwrap());
        s.insert(Capability::from_name("CAP_SYS_ADMIN").unwrap());
        s.insert(Capability::from_number(60).unwrap()); // not in the table
        assert_eq!(format!("{s:?}"), "{CAP_NET_RAW, CAP_SYS_ADMIN}");
        assert_eq!(format!("{:?}", CapSet::EMPTY), "{}");
    }

    #[test]
    fn from_arg_numeric_forms() {
        let n = |a: &str| Capability::from_arg(a).map(Capability::number);
        assert_eq!(n("0x10").unwrap(), 16);
        assert_eq!(n("010").unwrap(), 8);
        assert_eq!(n("63").unwrap(), 63);
        assert_eq!(n("5x").unwrap(), 5);
        assert!(n("64").is_err());
        assert!(n("99999999999999999999999").is_err());
        assert_eq!(n("+5").unwrap_err().to_string(), "unknown cap: +5");
        assert_eq!(n("cap_chown,x").unwrap(), 0);
        assert_eq!(n("nope").unwrap_err().to_string(), "unknown cap: nope");
    }
}
