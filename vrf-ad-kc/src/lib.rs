// Copyright (c) 2019-2020 Web 3 Foundation

//! # VRF-AD-KC
//! 
//! Implements two elliptic curve Verifiable random functions with
//! associated data called `ThinVRF` and `PedersenVRF`, the second of
//! which supports Pedersen key commitments for usage in anonymized
//! ring VRFs or group VRFs.
//!
//! 
//!


// #![feature(associated_type_defaults)]
// #![feature(array_methods)]


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



// #[cfg(test)]
// mod tests {
//     // use super::*;

//     // use rand::{SeedableRng, XorShiftRng};

//     // #[test]
//     // fn foo() { }
// }

