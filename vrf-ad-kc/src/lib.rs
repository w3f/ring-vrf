// Copyright (c) 2019-2020 Web 3 Foundation

//! # VRF-AD-KC
//! 
//! Implements two elliptic curve Verifiable random functions with
//! associated data called thin VRF aka `ThinVrf` and the Pedersen VRF
//! `PedersenVRF`, the second of which supports Pedersen key commitments
//! for usage in anonymized ring VRFs or group VRFs.


// #![feature(associated_type_defaults)]
// #![feature(array_methods)]

use ark_ec::{AffineCurve, ProjectiveCurve};

extern crate arrayref;

// #[cfg(feature = "serde")]
// extern crate serde;


pub mod error;
pub use error::{SignatureResult, SignatureError};

pub mod keys; // PublicKeyUnblinding
pub use keys::{PublicKey, SecretKey};

mod transcript;
pub use transcript::{SigningTranscript}; // signing_context

// #[cfg(feature = "merlin")]
// use merlin::Transcript;

pub mod vrf;
pub use vrf::{VrfPreOut, VrfInOut}; // signing_context

mod flavor;
pub use flavor::Flavor;

mod thin;
pub use thin::{ThinVrf};

mod pedersen;
pub use pedersen::{PedersenVrf};


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
pub const fn small_cofactor_projective<C: ProjectiveCurve>() -> bool {
    let cofactor: &'static [u64] = <C as ProjectiveCurve>::COFACTOR;
    if cofactor.len() == 0 { true }
    else if cofactor.len() == 1 && cofactor[0] <= SMALL_COFACTOR_BOUND { true }
    else { false }
}

/// Report if an elliptic curve has a small cofactor
/// 
/// We expect this gets used like: 
/// If false then perform full subgroups checks in deserialization
/// If true then only perform on-curve checks in deserialization,
/// but invoke `mul_by_cofactor` in hashing and equality checks. 
pub const fn small_cofactor<C: AffineCurve>() -> bool {
    small_cofactor_projective::<<C as AffineCurve>::Projective>()
}

pub fn eq_mod_small_cofactor_projective<C: ProjectiveCurve>(lhs: &C, rhs: &C) -> bool {
    if crate::small_cofactor_projective::<C>() {
        lhs.mul(<C as ProjectiveCurve>::COFACTOR) == rhs.mul(<C as ProjectiveCurve>::COFACTOR)
    } else { lhs == rhs }
}

pub fn eq_mod_small_cofactor_affine<C: AffineCurve>(lhs: &C, rhs: &C) -> bool {
    if crate::small_cofactor::<C>() {
        lhs.mul_by_cofactor() == rhs.mul_by_cofactor()
    } else { lhs == rhs }
}


// #[cfg(test)]
// mod tests {
//     // use super::*;

//     // use rand::{SeedableRng, XorShiftRng};

//     // #[test]
//     // fn foo() { }
// }

