// Copyright (c) 2019-2020 Web 3 Foundation

//! ### VRF keys

// use core::fmt::{Debug};

use ark_std::{UniformRand, io::{Read, Write}};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_serialize::{CanonicalSerialize,CanonicalDeserialize,SerializationError};

// use subtle::{Choice,ConstantTimeEq};
use rand_core::{RngCore,CryptoRng};

use zeroize::Zeroize;



/// Affine curve with VRF base points
pub trait VrfAffineCurve : AffineCurve {
    const SMALL_COFACTOR : bool = false;
    fn affine_clear_small_cofactor(&self) -> <Self as AffineCurve>::Projective {
        if Self::SMALL_COFACTOR {
            self.mul_by_cofactor_to_projective()
        } else { self.into_projective() }
    }
    fn projective_clear_small_cofactor(p: <Self as AffineCurve>::Projective) -> <Self as AffineCurve>::Projective {
        if Self::SMALL_COFACTOR {
            p.mul(<<Self as AffineCurve>::Projective as ProjectiveCurve>::COFACTOR)
        } else { p }
    }

    fn publickey_base_affine() -> Self;
    fn publickey_base_projective() -> <Self as AffineCurve>::Projective {
        Self::publickey_base_affine().into_projective()
    }

    fn blinding_base_affine() -> Self;
    fn blinding_base_projective() -> <Self as AffineCurve>::Projective {
        Self::blinding_base_affine().into_projective()
    }
}


/// Public key
#[derive(Debug,Clone,CanonicalSerialize,CanonicalDeserialize)] // Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, CanonicalSerialize,CanonicalDeserialize
pub struct PublicKey<C: VrfAffineCurve>(pub(crate) C);

impl<C: VrfAffineCurve> PublicKey<C> {
    fn from_secret_scalar(secret: <C as AffineCurve>::ScalarField) -> Self {
        PublicKey( C::publickey_base_affine().mul(secret).into_affine() )
    }
}

// impl_ark_serialize!(PublicKey);
// serde_boilerplate!(PublicKey);

impl<C: VrfAffineCurve> PartialEq for PublicKey<C> {
    fn eq(&self, other: &PublicKey<C>) -> bool {
        self.0.mul_by_cofactor() == other.0.mul_by_cofactor()
    }
}
impl<C: VrfAffineCurve> Eq for PublicKey<C> {}


/// Pederson commitment openning for a public key, consisting of a scalar
/// that reveals the difference ebtween two public keys.
#[derive(Clone,CanonicalSerialize,CanonicalDeserialize)] // Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash
pub struct PublicKeyUnblinding<C: VrfAffineCurve>(pub(crate) <C as AffineCurve>::ScalarField);

// impl_ark_serialize!(PublicKeyUnblinding);  FIX
// serde_boilerplate!(PublicKeyUnblinding);

impl<C: VrfAffineCurve> Zeroize for PublicKeyUnblinding<C> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl<C: VrfAffineCurve> Drop for PublicKeyUnblinding<C> {
    fn drop(&mut self) { self.zeroize() }
}

impl<C: VrfAffineCurve> PublicKeyUnblinding<C> {
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


/// Length of the nonce seed accompanying the secret key.
pub const NONCE_SEED_LENGTH: usize = 32;


/// Seceret key consisting of a scalar and a secret nonce seed.
#[derive(Clone)] // Debug
pub struct SecretKey<C: VrfAffineCurve> {
    /// Secret key represented as a scalar.
    pub(crate) key: <C as AffineCurve>::ScalarField,

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
    public: PublicKey<C>,
}



// serde_boilerplate!(SecretKey);

impl<C: VrfAffineCurve> Zeroize for SecretKey<C> {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.nonce_seed.zeroize();
    }
}
impl<C: VrfAffineCurve> Drop for SecretKey<C> {
    fn drop(&mut self) { self.zeroize() }
}

/*
impl<C: VrfAffineCurve> Debug for SecretKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "SecretKey {{ key: {:?} nonce: {:?} }}", &self.key, &self.nonce)
    }
}

impl<C: VrfAffineCurve> Eq for SecretKey {}
impl<C: VrfAffineCurve> PartialEq for SecretKey<C> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).unwrap_u8() == 1u8
    }
}
impl<C: VrfAffineCurve> ConstantTimeEq for SecretKey<C> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.key.ct_eq(&other.key)
    }
}
*/


impl<C: VrfAffineCurve> SecretKey<C> {
    /// Generate an "unbiased" `SecretKey` directly from a user
    /// suplied `csprng` uniformly, bypassing the `MiniSecretKey`
    /// layer.
    pub fn from_rng<R>(rng: &mut R) -> Self
    where R: CryptoRng + RngCore,
    {
        let mut nonce_seed: [u8; 32] = [0u8; 32];
        rng.fill_bytes(&mut nonce_seed);
        let key = <<C as AffineCurve>::ScalarField as UniformRand>::rand(rng);
        let public = PublicKey::from_secret_scalar(key);
        SecretKey { key, nonce_seed, public, }
    }

    /// Generate a JubJub `SecretKey` from a 32 byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        use rand_core::SeedableRng;
        let mut rng = ::rand_chacha::ChaChaRng::from_seed(seed);
        SecretKey::from_rng(&mut rng)
    }

    /// Generate a JubJub `SecretKey` with the default randomness source.
    #[cfg(feature = "std")]
    pub fn new() -> Self {
        SecretKey::from_rng(::rand::thread_rng())
    }

    /// Reference the `PublicKey` corresponding to this `SecretKey`.
    pub fn as_publickey(&self) -> &PublicKey<C> { &self.public }

    /// Clone the `PublicKey` corresponding to this `SecretKey`.
    pub fn to_public(&self) -> PublicKey<C> { self.public.clone() }
}
// TODO:  Convert to/from zcash_primitives::redjubjub::PrivateKey


impl<C: VrfAffineCurve+CanonicalSerialize> CanonicalSerialize for SecretKey<C> {
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
    fn serialize_uncompressed<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        writer.write_all(&self.nonce_seed) ?;
        self.key.serialize_uncompressed(writer)
    }

    #[inline]
    fn serialize_unchecked<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        writer.write_all(&self.nonce_seed) ?;
        self.key.serialize_unchecked(writer)
    }

    #[inline]
    fn uncompressed_size(&self) -> usize {
        self.key.uncompressed_size() + NONCE_SEED_LENGTH
    }
}

impl<C: VrfAffineCurve+CanonicalSerialize> CanonicalDeserialize for SecretKey<C> {
    #[inline]
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let key = <C as AffineCurve>::ScalarField::deserialize(&mut reader) ?;
        let mut nonce_seed = [0u8; 32];
        reader.read_exact(&mut nonce_seed) ?;
        let public = PublicKey::from_secret_scalar(key);
        Ok(SecretKey { key, nonce_seed, public, })
    }

    #[inline]
    fn deserialize_uncompressed<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let key = <C as AffineCurve>::ScalarField::deserialize_uncompressed(&mut reader) ?;
        let mut nonce_seed = [0u8; 32];
        reader.read_exact(&mut nonce_seed) ?;
        let public = PublicKey::from_secret_scalar(key);
        Ok(SecretKey { key, nonce_seed, public, })
    }

    #[inline]
    fn deserialize_unchecked<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let key = <C as AffineCurve>::ScalarField::deserialize_unchecked(&mut reader) ?;
        let mut nonce_seed = [0u8; 32];
        reader.read_exact(&mut nonce_seed) ?;
        let public = PublicKey::from_secret_scalar(key);
        Ok(SecretKey { key, nonce_seed, public, })
    }
}

