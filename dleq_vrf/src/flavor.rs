// Copyright (c) 2019-2020 Web 3 Foundation

//! # Architecture
//! 
//! Our two signatures each handle different public v secret flavors,
//! a regular `public = secret * base`, and also a Pedersen commitment
//! like `public = secret * base + blinding_secret * BlindingBase`.
//! A signature creates fresh a `Witness { k, r }` pair, computes a
//! challenge scalar via Fiat-Shamir, and then as proof reveals the
//! secret-like component of `k + challenge * public`.
//! 
//! `ThinVrf` has only one verification equation of the regular flavor,
//! in which we choose base to be a delinearized combination of the
//! signer's public key base and the `VrfInput` bases.
//! 
//! `PedersenVrf` has one verification equation of each flavor, but
//! which share the same challenge.  In this, `Witness::k` has nonces
//! for both the public key and blinding base, and `Witness::r` has
//! curve points for both the keying curve and the hashing curve
//! 
//! ### Batching
//! 
//! An EC VRF cannot save any space through half-aggregation aka
//! pre-batching, as sending two nonces point consumes the space saved
//! by sending one less scalar.  Yet, our `ThinVrf` and `PedersenVrf`
//! both do save space when half-aggregated aka pre-batched.
//! `ThinVrf` needs only one nonces point.  `PedersenVrf` needs two
//! nonce points, but also needs two scalars, which then merge in
//! half-aggregation aka pre-batching, again saving 50%.   We thus
//! choose batch verifiable forms for both signature flavors.
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

use ark_ff::{PrimeField};
use ark_ec::{AffineRepr};

use ark_serialize::{CanonicalSerialize,CanonicalDeserialize,SerializationError};
use ark_std::{vec::Vec, io::{Read,Write}};


/// VRF flavors based upon DLEQ proofs: Thin/Schnorr vs Pedersen vs something else.
/// 
/// TODO: Use hash-to-field instead of UniformRand for Scalars.
pub trait Flavor : InnerFlavor {
    type ScalarField:  PrimeField + Into<<Self::ScalarField as PrimeField>::BigInt>;
    type KeyAffine:    AffineRepr<ScalarField = Self::ScalarField>;
    type PreOutAffine: AffineRepr<ScalarField = Self::ScalarField>;

    fn keying_base(&self) -> &Self::KeyAffine;
}

pub trait InnerFlavor: Eq + PartialEq {
    type KeyCommitment: ark_std::fmt::Debug + Clone + Eq + PartialEq + CanonicalSerialize + CanonicalDeserialize;
    type Scalars: ark_std::fmt::Debug + Clone + Eq + PartialEq + CanonicalSerialize + CanonicalDeserialize + Default + zeroize::Zeroize;
    type Affines: ark_std::fmt::Debug + Clone + Eq + PartialEq + CanonicalSerialize + CanonicalDeserialize;
}

/// Secret and public nonce/witness for doing one signature,
/// obvoiusly usable only once ever.
pub(crate) struct Witness<F: Flavor> {
    pub(crate) k: <F as InnerFlavor>::Scalars,
    pub(crate) r: <F as InnerFlavor>::Affines,
}

/// Batchable VRF signature detached from VRF inputs and outpus
#[derive(Debug,Clone,Eq,PartialEq,CanonicalSerialize,CanonicalDeserialize)]
pub struct Batchable<F: Flavor> {
    pub(crate) compk: <F as InnerFlavor>::KeyCommitment,
    pub(crate) s: <F as InnerFlavor>::Scalars,
    pub(crate) r: <F as InnerFlavor>::Affines,
}

/*
impl<P: Flavor> Valid for Batchable<F> {
    fn check(&self) -> Result<(), SerializationError> {
        if self.is_on_curve() && self.is_in_correct_subgroup_assuming_on_curve() {
            Ok(())
        } else {
            Err(SerializationError::InvalidData)
        }
    }
}
*/

/// Arkworks' own serialization traits should be preferred over these.
impl<F: Flavor> Batchable<F> {
    pub fn as_key_commitment(&self) -> &<F as InnerFlavor>::KeyCommitment { &self.compk }

    pub fn size_of_serialized(&self) -> usize {
        self.compressed_size()
    }

    pub fn serialize<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        self.serialize_compressed(writer)
    }

    pub fn deserialize<R: Read>(reader: R) -> Result<Self, SerializationError> {
        Self::deserialize_compressed(reader)
    }
}

/// Non-batchable VRF signature detached from VRF inputs and outpus,resembles EC VRF.
#[derive(Debug,Clone,Eq,PartialEq,CanonicalSerialize,CanonicalDeserialize)]
pub struct NonBatchable<F: Flavor> 
// where K: AffineRepr, H: AffineRepr<ScalarField = K::ScalarField>,
{
    pub(crate) compk: <F as InnerFlavor>::KeyCommitment,
    pub(crate) s: <F as InnerFlavor>::Scalars,
    pub(crate) c: <F as Flavor>::ScalarField,
}

/// Arkworks' own serialization traits should be preferred over these.
impl<F: Flavor> NonBatchable<F> {
    pub fn as_key_commitment(&self) -> &<F as InnerFlavor>::KeyCommitment { &self.compk }

    pub fn size_of_serialized(&self) -> usize {
        self.compressed_size()
    }

    pub fn serialize<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        self.serialize_compressed(writer)
    }

    pub fn deserialize<R: Read>(reader: R) -> Result<Self, SerializationError> {
        Self::deserialize_compressed(reader)
    }
}
