// Copyright (c) 2019-2020 Web 3 Foundation

//! ### VRF keys

// use core::fmt::{Debug};

use ark_std::{UniformRand, io::{Read, Write}};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_serialize::{CanonicalSerialize,CanonicalDeserialize,SerializationError};

// use subtle::{Choice,ConstantTimeEq};
use rand_core::{RngCore,CryptoRng};

use zeroize::Zeroize;

use crate::flavor::Flavor;


/// Public key
#[derive(Debug,Clone,CanonicalSerialize,CanonicalDeserialize)] // Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, CanonicalSerialize,CanonicalDeserialize
pub struct PublicKey<C: AffineCurve>(pub(crate) C);
 
fn new_public<F: Flavor>(
    flavor: &F,
    secret: <<F as Flavor>::AffineKey as AffineCurve>::ScalarField
) -> PublicKey<<F as Flavor>::AffineKey>
{
    PublicKey( flavor.publickey_base().mul(secret).into_affine() )
}

// <F as Flavor>::AffineKey as AffineCurve

// impl_ark_serialize!(PublicKey);
// serde_boilerplate!(PublicKey);

impl<C: AffineCurve> PartialEq for PublicKey<C> {
    fn eq(&self, other: &PublicKey<C>) -> bool {
        crate::eq_mod_small_cofactor_affine(&self.0, &other.0)
    }
}
impl<C: AffineCurve> Eq for PublicKey<C> {}


/*
/// Pederson commitment openning for a public key, consisting of a scalar
/// that reveals the difference ebtween two public keys.
#[derive(Clone,CanonicalSerialize,CanonicalDeserialize)] // Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash
pub struct PublicKeyUnblinding<C: AffineCurve>(pub(crate) <C as AffineCurve>::ScalarField);

// impl_ark_serialize!(PublicKeyUnblinding);  FIX
// serde_boilerplate!(PublicKeyUnblinding);

impl<C: AffineCurve> Zeroize for PublicKeyUnblinding<C> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl<C: AffineCurve> Drop for PublicKeyUnblinding<C> {
    fn drop(&mut self) { self.zeroize() }
}

impl<C: AffineCurve> PublicKeyUnblinding<C> {
    pub fn is_blinded(&self) -> bool {
        use ark_ff::Zero;
        self.0.is_zero() // != <<C as AffineCurve>::ScalarField as Zero>::zero()
    }

    pub fn verify(&self, blinded: PublicKey<C>, unblinded: PublicKey<C>) -> bool {
        let mut b = C::blinding_base_affine().mul(self.0);
        b.add_assign_mixed(& unblinded.0);
        // b.mul(<<C as AffineCurve>::Projective as ProjectiveCurve>::COFACTOR) // into_affine seems silly here
        b.into_affine().mul_by_cofactor_to_projective() == blinded.0.mul_by_cofactor_to_projective()
    }
}
*/


/// Length of the nonce seed accompanying the secret key.
pub const NONCE_SEED_LENGTH: usize = 32;


/// Seceret key consisting of a scalar and a secret nonce seed.
#[derive(Clone)] // Debug
pub struct SecretKey<F: Flavor> {
    pub(crate) flavor: F,

    /// Secret key represented as a scalar.
    pub(crate) key: <<F as Flavor>::AffineKey as AffineCurve>::ScalarField,

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
    public: PublicKey<<F as Flavor>::AffineKey>,
}

// <F as Flavor>::AffineKey as AffineCurve

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
        let key = <<<F as Flavor>::AffineKey as AffineCurve>::ScalarField as UniformRand>::rand(rng);
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
    #[cfg(feature = "std")]
    pub fn new(flavor: F) -> Self {
        SecretKey::from_rng(flavor, ::rand::thread_rng())
    }

    /// Reference the `PublicKey` corresponding to this `SecretKey`.
    pub fn as_publickey(&self) -> &PublicKey<<F as Flavor>::AffineKey> { &self.public }

    /// Clone the `PublicKey` corresponding to this `SecretKey`.
    pub fn to_public(&self) -> PublicKey<<F as Flavor>::AffineKey> { self.public.clone() }

    #[inline]
    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        writer.write_all(&self.nonce_seed) ?;
        self.key.serialize(writer)
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        self.key.serialized_size() + NONCE_SEED_LENGTH
    }

    #[inline]
    fn deserialize<R: Read>(flavor: F, mut reader: R) -> Result<Self, SerializationError> {
        let key = <<F as Flavor>::AffineKey as AffineCurve>::ScalarField::deserialize(&mut reader) ?;
        let mut nonce_seed = [0u8; 32];
        reader.read_exact(&mut nonce_seed) ?;
        let public = new_public(&flavor,key);
        Ok(SecretKey { flavor, key, nonce_seed, public, })
    }
}
// TODO:  Convert to/from zcash_primitives::redjubjub::PrivateKey

