// Copyright (c) 2019-2020 Web 3 Foundation

//! # Architecture
//! 
//! Our two signatures each handle different public v secret flavors,
//! a regular `Public = Secret * Base`, and also a Pedersen commitment
//! like `Public = Secret * Base + BlindingSecret * BlindingBase`.
//! A signature creates a `k: NonceSecret` and `NoncePublic` pair,
//! computes a challenge scalar via Fiat-Shamir, and then as proof reveals
//! the secret-like component of `NoncePublic + Challenge * Public`.
//! 
//! `ThinVrf` has only one verification equation of the regular flavor,
//! in which we choose base to be a delinearized combination of the
//! signer's public key base and the `VrfInput` bases.
//! 
//! `PedersenVrf` has one verification equation of each flavor, with
//! seperate `NoncePublic`s, but which share the same challenge, and
//! the regular proof is a prefix of the Pedersen proof.
//! 
//! ### Batching
//! 
//! We support half-aggregation aka pre-batching for both, which retains
//! each signature's own distinct `NoncePublic`s, and other publics, but
//! only retains a delinearized combination of the proof proof components,
//! and thereby merges the verification equations.
//!  
//! ### Multi-signatures
//!
//! A two-round multi-signatures work like: 
//! 
//! Round 1. Create distinct random  `k1,k2: NonePublic`.  Also compute
//! distinct corresponding `r1,r2: NonceSecret` for each `VrfInput` and
//! the public key base.  Share all these `(r1,r2,VrfPreOut)` tuples.
//! 
//! Round 2.
//! First, merge the public keys and each `VrfPreOut` from all signers,
//! acording to the DKG scheme.  Next, check honest multi-signature
//! inclusion, compute a delinearization factor `d`, the delinearized
//! `NonceSecret` given by `k = k1 + d * k2`, and the delinearized
//! `NoncePublic`s for each `VrfInput` and the public key base, again
//! given by `r = r1 + d r2`.
//! 
//! TODO:
//! Next, construct `ThinVrfWitness` and invoke `thin_vrf_merge`,
//! and `sign_final`.  We split `sign_final` components from `sign_thin_vrf` so this works cleanly.

use ark_ff::{PrimeField, SquareRootField};
use ark_ec::{AffineCurve, ProjectiveCurve};

/// VRF flavors based upon DLEQ proofs: Thin/Schnorr vs Pedersen vs something else.
/// 
/// TODO: Use hash-to-field instead of UniformRand for Scalars.
pub trait Flavor : sealed::InnerFlavor {
    type ScalarField:  PrimeField + SquareRootField;
    type KeyAffine:    AffineCurve<ScalarField = Self::ScalarField>;
    type PreOutAffine: AffineCurve<ScalarField = Self::ScalarField>;

    fn keying_base(&self) -> &Self::KeyAffine;
}

pub(crate) mod sealed {
    pub trait InnerFlavor {
    //    type Scalars: ;
    //    type Affines: ;
    }
}
