// Copyright (c) 2019-2020 Web 3 Foundation

//! ### Ring VRF keys

use core::fmt::{Debug};

// use subtle::{Choice,ConstantTimeEq};
use zeroize::Zeroize;
use rand_core::{RngCore,CryptoRng};

use ff::{Field, ScalarEngine};
use zcash_primitives::jubjub::{JubjubEngine, FixedGenerators, JubjubParams, PrimeOrder, edwards};

use crate::{Params};


/// Seceret key consisting of a JubJub scalar and a secret nonce seed.
#[derive(Debug,Clone)]
pub struct SecretKey<E: JubjubEngine> {
    /// Actual public key represented as a scalar.
    pub(crate) key: E::Fs,
    /// Seed for deriving the nonces used in Schnorr proofs.
    ///
    /// We require this be random and secret or else key compromise attacks will ensue.
    /// Any modificaiton here may dirupt some non-public key derivation techniques.
    pub(crate) nonce_seed: [u8; 32],
}

// serde_boilerplate!(SecretKey);

impl<E: JubjubEngine> Zeroize for SecretKey<E> {
    fn zeroize(&mut self) {
        self.nonce_seed.zeroize();
        // self.key.zeroize();
        // self.key = <E:Fs as PrimeField>::from_repr(<E:Fs as PrimeField>::Repr::default());
    }
}
impl<E: JubjubEngine> Drop for SecretKey<E> {
    fn drop(&mut self) { self.zeroize() }
}

/*
impl Debug for SecretKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "SecretKey {{ key: {:?} nonce: {:?} }}", &self.key, &self.nonce)
    }
}
*/

/*
impl Eq for SecretKey {}
impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).unwrap_u8() == 1u8
    }
}
impl ConstantTimeEq for SecretKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.key.ct_eq(&other.key)
    }
}
*/

impl<E: JubjubEngine> SecretKey<E> {
    /// Generate an "unbiased" `SecretKey` directly from a user
    /// suplied `csprng` uniformly, bypassing the `MiniSecretKey`
    /// layer.
    pub fn from_rng<R>(mut rng: R) -> SecretKey<E>
    where R: CryptoRng + RngCore,
    {
        let mut nonce_seed: [u8; 32] = [0u8; 32];
        rng.fill_bytes(&mut nonce_seed);
        let key = <E::Fs as ::ff::Field>::random(&mut rng);
        SecretKey { key, nonce_seed }
    }

    /// Generate a JubJub `SecretKey` from a 32 byte seed.
    pub fn from_seed(seed: [u8; 32]) -> SecretKey<E> {
        use rand_core::SeedableRng;
        let rng = ::rand_chacha::ChaChaRng::from_seed(seed);
        SecretKey::from_rng(rng)
    }

    /// Generate a JubJub `SecretKey` with the default randomness source.
    #[cfg(feature = "std")]
    pub fn new() -> SecretKey<E> {
        SecretKey::from_rng(::rand::thread_rng())
    }

    /// Derive the `PublicKey` corresponding to this `SecretKey`.
    pub fn to_public(&self, params: &Params<E>) -> PublicKey<E> {
        // Jubjub generator point. TODO: prime or ---
        let base_point = params.engine.generator(FixedGenerators::SpendingKeyGenerator);
        PublicKey( base_point.mul(self.key.clone(), &params.engine).to_xy().0 )
    }

    /// Derive the `Keypair` corresponding to this `SecretKey`.
    pub fn to_keypair(self, params: &Params<E>) -> Keypair<E> {
        let public = self.to_public(params);
        Keypair { secret: self, public }
    }
}



// was pub type PublicKey<E> = <E as ScalarEngine>::Fr;

/// Public key consisting of a JubJub point
#[derive(Clone)] // Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash
pub struct PublicKey<E: JubjubEngine>(pub(crate) <E as ScalarEngine>::Fr);

// serde_boilerplate!(PublicKey);

// impl<E: JubjubEngine> PublicKey<E> {
// }


pub struct Keypair<E: JubjubEngine> {
    /// The secret half of this keypair.
    pub secret: SecretKey<E>,
    /// The public half of this keypair.
    pub public: PublicKey<E>,
}

impl<E: JubjubEngine> Zeroize for Keypair<E> {
    fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}
impl<E: JubjubEngine> Drop for Keypair<E> {
    fn drop(&mut self) { self.zeroize() }
}


// serde_boilerplate!(Keypair);

impl<E: JubjubEngine> Keypair<E> {
    /// Generate a JubJub `Keypair` from a user suplied `Rng`.
    pub fn from_rng<R>(csprng: R, params: &Params<E>) -> Keypair<E>
    where R: CryptoRng + RngCore,
    {
        let secret = SecretKey::from_rng(csprng);
        let public = secret.to_public(params);
        Keypair{ public, secret }
    }

    /// Generate a JubJub `SecretKey` from a 32 byte seed.
    pub fn from_seed(seed: [u8; 32], params: &Params<E>) -> Keypair<E> {
        use rand_core::SeedableRng;
        let rng = ::rand_chacha::ChaChaRng::from_seed(seed);
        Keypair::from_rng(rng, params)
    }

    /// Generate a JubJub `Keypair` with the default randomness source.
    #[cfg(feature = "std")]
    pub fn generate(params: &Params<E>) -> Keypair<E> {
        Keypair::from_rng(::rand::thread_rng(), params)
    }
}
