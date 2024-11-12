use crate::error::{Error, PatternProblem};
use std::str::FromStr;

/// This macro is specifically a helper to generate the enum of all handshake
/// patterns in a less error-prone way.
///
/// While rust macros can be really difficult to read, it felt too sketchy to hand-
/// write a growing list of str -> enum variant match statements.
macro_rules! pattern_enum {
    // NOTE: see https://danielkeep.github.io/tlborm/book/mbe-macro-rules.html and
    // https://doc.rust-lang.org/rust-by-example/macros.html for a great overview
    // of `macro_rules!`.
    ($name:ident {
        $($variant:ident),* $(,)*
    }) => {
        /// One of the patterns as defined in the
        /// [Handshake Pattern](https://noiseprotocol.org/noise.html#handshake-patterns)
        /// section.
        #[allow(missing_docs)]
        #[derive(Copy, Clone, PartialEq, Debug)]
        pub enum $name {
            $($variant),*,
        }

        impl FromStr for $name {
            type Err = Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                use self::$name::*;
                match s {
                    $(
                        stringify!($variant) => Ok($variant)
                    ),
                    *,
                    _    => return Err(PatternProblem::UnsupportedHandshakeType.into())
                }
            }
        }

        impl $name {
            /// The equivalent of the `ToString` trait, but for `&'static str`.
            pub fn as_str(self) -> &'static str {
                use self::$name::*;
                match self {
                    $(
                        $variant => stringify!($variant)
                    ),
                    *
                }
            }
        }

        #[doc(hidden)]
        pub const SUPPORTED_HANDSHAKE_PATTERNS: &'static [$name] = &[$($name::$variant),*];
    }
}

// See the documentation in the macro above.
pattern_enum! {
    HandshakePattern {
        // 7.4. One-way handshake patterns
        N, X, K,

        // 7.5. Interactive handshake patterns (fundamental)
        NN, NK, NX, XN, XK, XX, KN, KK, KX, IN, IK, IX,

        // 7.6. Interactive handshake patterns (deferred)
        NK1, NX1, X1N, X1K, XK1, X1K1, X1X, XX1, X1X1, K1N, K1K, KK1, K1K1, K1X,
        KX1, K1X1, I1N, I1K, IK1, I1K1, I1X, IX1, I1X1
    }
}

impl HandshakePattern {
    /// If the protocol is one-way only
    ///
    /// See: https://noiseprotocol.org/noise.html#one-way-handshake-patterns
    pub fn is_oneway(self) -> bool {
        matches!(self, N | X | K)
    }

    /// Whether this pattern requires a long-term static key.
    pub fn needs_local_static_key(self, initiator: bool) -> bool {
        if initiator {
            !matches!(self, N | NN | NK | NX | NK1 | NX1)
        } else {
            !matches!(self, NN | XN | KN | IN | X1N | K1N | I1N)
        }
    }

    /// Whether this pattern demands a remote public key pre-message.
    #[rustfmt::skip]
    pub fn need_known_remote_pubkey(self, initiator: bool) -> bool {
        if initiator {
            matches!(
                self,
                N | K | X | NK | XK | KK | IK | NK1 | X1K | XK1 | X1K1 | K1K | KK1 | K1K1 | I1K | IK1 | I1K1
            )
        } else {
            matches!(
                self,
                K | KN | KK | KX | K1N | K1K | KK1 | K1K1 | K1X | KX1 | K1X1
            )
        }
    }
}

/// A modifier applied to the base pattern as defined in the Noise spec.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum HandshakeModifier {
    /// Insert a PSK to mix at the associated position
    Psk(u8),

    /// Modify the base pattern to its "fallback" form
    Fallback,

    #[cfg(feature = "hfs")]
    /// Modify the base pattern to use Hybrid-Forward-Secrecy
    Hfs,
}

impl FromStr for HandshakeModifier {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            s if s.starts_with("psk") => {
                Ok(HandshakeModifier::Psk(s[3..].parse().map_err(|_| PatternProblem::InvalidPsk)?))
            },
            "fallback" => Ok(HandshakeModifier::Fallback),
            #[cfg(feature = "hfs")]
            "hfs" => Ok(HandshakeModifier::Hfs),
            _ => Err(PatternProblem::UnsupportedModifier.into()),
        }
    }
}

/// Handshake modifiers that will be used during key exchange handshake.
#[derive(Clone, PartialEq, Debug)]
pub struct HandshakeModifierList {
    /// List of parsed modifiers.
    pub list: Vec<HandshakeModifier>,
}

impl FromStr for HandshakeModifierList {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            Ok(HandshakeModifierList { list: vec![] })
        } else {
            let modifier_names = s.split('+');
            let mut modifiers = vec![];
            for modifier_name in modifier_names {
                let modifier: HandshakeModifier = modifier_name.parse()?;
                if modifiers.contains(&modifier) {
                    return Err(Error::Pattern(PatternProblem::UnsupportedModifier));
                } else {
                    modifiers.push(modifier);
                }
            }
            Ok(HandshakeModifierList { list: modifiers })
        }
    }
}

/// The pattern/modifier combination choice (no primitives specified)
/// for a full noise protocol definition.
#[derive(Clone, PartialEq, Debug)]
pub struct HandshakeChoice {
    /// The base pattern itself
    pub pattern: HandshakePattern,

    /// The modifier(s) requested for the base pattern
    pub modifiers: HandshakeModifierList,
}

impl HandshakeChoice {
    /// Whether the handshake choice includes one or more PSK modifiers.
    pub fn is_psk(&self) -> bool {
        for modifier in &self.modifiers.list {
            if let HandshakeModifier::Psk(_) = *modifier {
                return true;
            }
        }
        false
    }

    /// Whether the handshake choice includes the fallback modifier.
    pub fn is_fallback(&self) -> bool {
        self.modifiers.list.contains(&HandshakeModifier::Fallback)
    }

    /// Whether the handshake choice includes the hfs modifier.
    #[cfg(feature = "hfs")]
    pub fn is_hfs(&self) -> bool {
        self.modifiers.list.contains(&HandshakeModifier::Hfs)
    }

    /// Parse and split a base HandshakePattern from its optional modifiers
    fn parse_pattern_and_modifier(s: &str) -> Result<(HandshakePattern, &str), Error> {
        for i in (1..=4).rev() {
            if s.len() > i - 1 && s.is_char_boundary(i) {
                if let Ok(p) = s[..i].parse() {
                    return Ok((p, &s[i..]));
                }
            }
        }

        Err(PatternProblem::UnsupportedHandshakeType.into())
    }
}

impl FromStr for HandshakeChoice {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (pattern, remainder) = Self::parse_pattern_and_modifier(s)?;
        let modifiers = remainder.parse()?;

        Ok(HandshakeChoice { pattern, modifiers })
    }
}

use self::HandshakePattern::*;
