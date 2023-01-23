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
pub use keys::{PublicKey, SecretKey, VrfAffineCurve};

mod transcript;
pub use transcript::{SigningTranscript}; // signing_context

pub mod vrf;
pub use vrf::{VrfPreOut, VrfInOut}; // signing_context

pub mod thin;


/// Any cofactor of this size or smaller gets treated as small,
/// resulting in only doing on-curve checks, not full subgroup
/// checks, and instead multiplying by the cofactor in hashing
/// and equality checks.
const SMALL_COFACTOR_BOUND: u64 = 8;


/// Report if an elliptic curve has a small cofactor
/// 
/// We expect this gets used like: 
/// If false then perform full subgroups checks in deserialization
/// If true then only perform on-curve checks in deserialization,
/// but invoke `mul_by_cofactor` in hashing and equality checks. 
pub const fn small_cofactor<C: AffineCurve>() -> bool {
    let cofactor: &'static [u64] = <<C as AffineCurve>::Projective as ProjectiveCurve>::COFACTOR;
    if cofactor.len() == 0 { true }
    else if cofactor.len() == 1 && cofactor[0] <= SMALL_COFACTOR_BOUND { true }
    else { false }
}


// #[cfg(test)]
// mod tests {
//     // use super::*;

//     // use rand::{SeedableRng, XorShiftRng};

//     // #[test]
//     // fn foo() { }
// }

