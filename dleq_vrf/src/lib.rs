// Copyright (c) 2022-2023 Web 3 Foundation

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![doc = include_str!("../README.md")]


// #![feature(associated_type_defaults)]
// #![feature(array_methods)]

use ark_ec::{AffineRepr, CurveGroup, models::CurveConfig};

pub use ark_transcript::{self as transcript, Transcript, IntoTranscript};

pub mod error;
pub use error::{SignatureResult, SignatureError};

// InnerFlavor is a sealed trait, so no pub here.
mod flavor;
pub use flavor::{Flavor, Batchable, NonBatchable};

pub mod keys; // PublicKeyUnblinding
pub use keys::{PublicKey, SecretKey};

pub mod vrf;
pub use vrf::{IntoVrfInput, VrfInput, VrfPreOut, VrfInOut};

mod thin;
pub use thin::{ThinVrf,ThinVrfProof};

mod pedersen;
pub use pedersen::{PedersenVrf};

// #[cfg(feature = "getrandom")]
// mod musig

#[cfg(feature = "scale")]
pub mod scale;

pub mod traits;
pub use traits::{
    EcVrfSecret,EcVrfProof,EcVrfVerifier,EcVrfSigner,
    VrfSignature,VrfSignatureVec,
};

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
pub fn small_cofactor_affine<C: AffineRepr>() -> bool {
    small_cofactor_projective::<<C as AffineRepr>::Group>()
}

pub fn mul_by_small_cofactor<C: CurveGroup>(z: C) -> C {
    if crate::small_cofactor_projective::<C>() {
        z.mul_bigint(<<C as CurveGroup>::Config as CurveConfig>::COFACTOR)
    } else { z }
}

pub fn zero_mod_small_cofactor<C: CurveGroup>(z: C) -> bool {
    // use ark_ff::Zero;
    mul_by_small_cofactor(z).is_zero()
}

/*
pub fn zero_mod_small_cofactor_affine<C: AffineRepr>(z: C) -> bool {
    use ark_ff::Zero;
    if crate::small_cofactor::<C>() {
        z.clear_cofactor().is_zero() // mul_by_cofactor is fine here though
    } else { z.is_zero() }
}
*/


// #[cfg(test)]
// mod tests {
//     // use super::*;

//     // use rand::{SeedableRng, XorShiftRng};

//     // #[test]
//     // fn foo() { }
// }

