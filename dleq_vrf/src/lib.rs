// Copyright (c) 2022-2023 Web 3 Foundation

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![doc = include_str!("../README.md")]


// #![feature(associated_type_defaults)]
// #![feature(array_methods)]

use ark_ec::{AffineRepr, CurveGroup, models::CurveConfig};


pub mod error;
pub use error::{SignatureResult, SignatureError};

// InnerFlavor is a sealed trait, so no pub here.
mod flavor;
pub use flavor::{Flavor, Signature, NonBatchableSignature};

pub mod keys; // PublicKeyUnblinding
pub use keys::{PublicKey, SecretKey};
pub(crate) use keys::SecretPair;

// #[cfg(not(feature = "transcript_io"))]
// mod transcript;
// #[cfg(feature = "transcript_io")]
pub mod transcript;
pub use transcript::{SigningTranscript}; // signing_context

// #[cfg(feature = "merlin")]
pub use merlin::Transcript;

pub mod vrf;
pub use vrf::{IntoVrfInput, VrfInput, VrfPreOut, VrfInOut};

mod thin;
pub use thin::{ThinVrf};

mod pedersen;
pub use pedersen::{PedersenVrf};

// #[cfg(feature = "getrandom")]
// mod musig

#[cfg(test)]
mod tests;


/// Any cofactor of this size or smaller gets treated as small,
/// resulting in only doing on-curve checks, not full subgroup
/// checks, and instead multiplying by the cofactor in hashing
/// and equality checks.
pub const SMALL_COFACTOR_BOUND: u64 = 8;

/// Report if an elliptic curve has a small cofactor
/// 
/// We expect this gets used like: 
/// If false then perform full subgroups checks in deserialization
/// If true then only perform on-curve checks in deserialization,
/// but invoke `mul_by_cofactor` in hashing and equality checks. 
pub const fn small_cofactor_projective<C: CurveGroup>() -> bool {
    let cofactor: &'static [u64] = <<C as CurveGroup>::Config as CurveConfig>::COFACTOR;
    cofactor.len() == 0 || ( cofactor.len() == 1 && cofactor[0] <= SMALL_COFACTOR_BOUND )
}

/// Report if an elliptic curve has a small cofactor
/// 
/// We expect this gets used like: 
/// If false then perform full subgroups checks in deserialization
/// If true then only perform on-curve checks in deserialization,
/// but invoke `mul_by_cofactor` in hashing and equality checks. 
pub const fn small_cofactor<C: AffineRepr>() -> bool {
    small_cofactor_projective::<<C as AffineRepr>::Group>()
}

pub fn eq_mod_small_cofactor_projective<C: CurveGroup>(lhs: &C, rhs: &C) -> bool {
    if crate::small_cofactor_projective::<C>() {
        lhs.mul_bigint(<<C as CurveGroup>::Config as CurveConfig>::COFACTOR)
         == rhs.mul_bigint(<<C as CurveGroup>::Config as CurveConfig>::COFACTOR)
    } else { lhs == rhs }
}

pub fn eq_mod_small_cofactor_affine<C: AffineRepr>(lhs: &C, rhs: &C) -> bool {
    if crate::small_cofactor::<C>() {
        lhs.clear_cofactor() == rhs.clear_cofactor() // mul_by_cofactor is fine here though
    } else { lhs == rhs }
}


// #[cfg(test)]
// mod tests {
//     // use super::*;

//     // use rand::{SeedableRng, XorShiftRng};

//     // #[test]
//     // fn foo() { }
// }

