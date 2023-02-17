// Copyright (c) 2019-2020 Web 3 Foundation

//! ### VRF keys

// use core::fmt::{Debug};

use ark_std::{UniformRand, io::{Read, Write}};
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::{CanonicalSerialize,CanonicalDeserialize,SerializationError};

// use subtle::{Choice,ConstantTimeEq};
use rand_core::{RngCore,CryptoRng};

use zeroize::Zeroize;

use crate::flavor::{Flavor};


/// Public key
#[derive(Debug,Clone,CanonicalSerialize,CanonicalDeserialize)] // Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, CanonicalSerialize,CanonicalDeserialize
pub struct PublicKey<C: AffineRepr>(pub(crate) C);
 
fn new_public<F: Flavor>(
    flavor: &F,
    secret: <<F as Flavor>::KeyAffine as AffineRepr>::ScalarField
) -> PublicKey<<F as Flavor>::KeyAffine>
{
    PublicKey( (*flavor.keying_base() * secret).into_affine() )
}

impl<C: AffineRepr> PartialEq for PublicKey<C> {
    fn eq(&self, other: &PublicKey<C>) -> bool {
        crate::eq_mod_small_cofactor_affine(&self.0, &other.0)
    }
}
impl<C: AffineRepr> Eq for PublicKey<C> {}



/// Length of the nonce seed accompanying the secret key.
pub const NONCE_SEED_LENGTH: usize = 32;


/// Seceret key consisting of a scalar and a secret nonce seed.
#[derive(Clone)] // Debug
pub struct SecretKey<F: Flavor> {
    /// VRF signature flavor which specifies base points
    /// TODO: Can we make this be &'static F somehow?
    pub(crate) flavor: F,

    /// Secret key represented as a scalar.
    pub(crate) key: <<F as Flavor>::KeyAffine as AffineRepr>::ScalarField,

    /// Seed for deriving the nonces used in Schnorr proofs.
    ///
    /// We require this be random and secret or else key compromise attacks will ensue.
    /// Any modificaiton here may dirupt some non-public key derivation techniques.
    pub(crate) nonce_seed: [u8; NONCE_SEED_LENGTH],

    /// Public key represented as an alliptic curve point.
    ///
    /// We make our secret key into a keypair by retaining this because
    /// we must hash it when doing schnorr DLEQ proof based VRF signatures.
    ///
    /// TODO: Replace this with serialized byte representation like [u8; 32]
    /// TODO: Compjute lazilty using usafe code and std::sync::Once
    public: PublicKey<<F as Flavor>::KeyAffine>,
}

// <F as Flavor>::KeyAffine as AffineRepr

// serde_boilerplate!(SecretKey);

impl<F: Flavor> Zeroize for SecretKey<F> {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.nonce_seed.zeroize();
    }
}
impl<F: Flavor> Drop for SecretKey<F> {
    fn drop(&mut self) { self.zeroize() }
}

/*
impl<F: Flavor> Debug for SecretKey<F> {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "SecretKey {{ key: {:?} nonce: {:?} }}", &self.key, &self.nonce)
    }
}

impl<F: Flavor> Eq for SecretKey<F> {}
impl<F: Flavor> PartialEq for SecretKey<F> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).unwrap_u8() == 1u8
    }
}
impl<F: Flavor> ConstantTimeEq for SecretKey<F> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.key.ct_eq(&other.key)
    }
}
*/


impl<F: Flavor> SecretKey<F> {
    /// Generate an "unbiased" `SecretKey` directly from a user
    /// suplied `csprng` uniformly, bypassing the `MiniSecretKey`
    /// layer.
    pub fn from_rng<R>(flavor: F, rng: &mut R) -> Self
    where R: CryptoRng + RngCore,
    {
        let mut nonce_seed: [u8; 32] = [0u8; 32];
        rng.fill_bytes(&mut nonce_seed);
        let key = <<<F as Flavor>::KeyAffine as AffineRepr>::ScalarField as UniformRand>::rand(rng);
        let public = new_public(&flavor,key);
        SecretKey { flavor, key, nonce_seed, public, }
    }

    /// Generate a `SecretKey` from a 32 byte seed.
    pub fn from_seed(flavor: F, seed: [u8; 32]) -> Self {
        use rand_core::SeedableRng;
        let mut rng = ::rand_chacha::ChaChaRng::from_seed(seed);
        SecretKey::from_rng(flavor, &mut rng)
    }

    /// Generate a `SecretKey` with the default randomness source.
    #[cfg(feature = "getrandom")]
    pub fn new(flavor: F) -> Self {
        SecretKey::from_rng(flavor, &mut ::rand_core::OsRng)
    }

    /// Reference the `PublicKey` corresponding to this `SecretKey`.
    pub fn as_publickey(&self) -> &PublicKey<<F as Flavor>::KeyAffine> { &self.public }

    /// Clone the `PublicKey` corresponding to this `SecretKey`.
    pub fn to_public(&self) -> PublicKey<<F as Flavor>::KeyAffine> { self.public.clone() }

    #[inline]
    pub fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        writer.write_all(&self.nonce_seed) ?;
        self.key.serialize_compressed(writer)
    }

    #[inline]
    pub fn serialized_size(&self) -> usize {
        self.key.compressed_size() + NONCE_SEED_LENGTH
    }

    #[inline]
    pub fn deserialize<R: Read>(flavor: F, mut reader: R) -> Result<Self, SerializationError> {
        let key = <<F as Flavor>::KeyAffine as AffineRepr>::ScalarField::deserialize_compressed(&mut reader) ?;
        let mut nonce_seed = [0u8; 32];
        reader.read_exact(&mut nonce_seed) ?;
        let public = new_public(&flavor,key);
        Ok(SecretKey { flavor, key, nonce_seed, public, })
    }
}
// TODO:  Convert to/from zcash_primitives::redjubjub::PrivateKey

