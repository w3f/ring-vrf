// Copyright (c) 2019-2020 Web 3 Foundation

//! ### Ring VRF keys

use std::io;
use std::ops::Add;
// use core::fmt::{Debug};

// use subtle::{Choice,ConstantTimeEq};
use rand_core::{RngCore,CryptoRng};

use zeroize::Zeroize;

use crate::{ReadWrite, Scalar};
use group::GroupEncoding;


/// Public key consisting of a JubJub point
#[derive(Debug,Clone)] // Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash
pub struct PublicKey(pub(crate) jubjub::ExtendedPoint);

// serde_boilerplate!(PublicKey);

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        self.0.mul_by_cofactor() == other.0.mul_by_cofactor()
    }
}

impl Eq for PublicKey {}

impl PublicKey {
    fn from_secret_scalar(secret: &Scalar) -> Self {
        PublicKey( crate::scalar_times_generator(secret).into() )
    }
}

impl ReadWrite for PublicKey {
    fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let mut bytes = [0u8; 32];
        reader.read_exact(&mut bytes)?;
        let p = jubjub::ExtendedPoint::from_bytes(&bytes);
        if p.is_none().into() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid public key encoding"));
        }
        Ok(PublicKey(p.unwrap()))
    }

    fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.0.to_bytes())
    }
}


/// Pederson commitment openning for a public key, consisting of a scalar
/// that reveals the difference ebtween two public keys.
#[derive(Clone)] // Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash
pub struct PublicKeyUnblinding(pub(crate) Scalar);

impl PublicKeyUnblinding {
    pub fn is_blinded(&self) -> bool {
        self.0 != Scalar::zero()
    }

    pub fn verify(&self, blinded: PublicKey, unblinded: PublicKey) -> bool {
        unblinded.0.add(& crate::scalar_times_generator(&self.0)).mul_by_cofactor()
        == blinded.0.mul_by_cofactor()
    }
}

impl ReadWrite for PublicKeyUnblinding  {
    fn read<R: io::Read>(reader: R) -> io::Result<Self> {
        Ok(PublicKeyUnblinding( crate::read_scalar::<R>(reader) ? ))
    }

    fn write<W: io::Write>(&self, writer: W) -> io::Result<()> {
        crate::write_scalar::<W>(&self.0, writer)
    }
}


/// Seceret key consisting of a JubJub scalar and a secret nonce seed.
#[derive(Clone)] // Debug
pub struct SecretKey {
    /// Secret key represented as a scalar.
    pub(crate) key: Scalar,

    /// Seed for deriving the nonces used in Schnorr proofs.
    ///
    /// We require this be random and secret or else key compromise attacks will ensue.
    /// Any modificaiton here may dirupt some non-public key derivation techniques.
    pub(crate) nonce_seed: [u8; 32],

    /// Public key represented as an alliptic curve point.
    ///
    /// We make our secret key into a keypair by retaining this because
    /// we must hash it when doing schnorr DLEQ proof based VRF signatures.
    ///
    /// TODO: Replace this with serialized byte representation like [u8; 32]
    /// TODO: Compjute lazilty using usafe code and std::sync::Once
    public: PublicKey,
}

// serde_boilerplate!(SecretKey);

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.nonce_seed.zeroize();
        // self.key.zeroize();
        // self.key = <E:Fs as PrimeField>::from_repr(<E:Fs as PrimeField>::Repr::default());
    }
}
impl Drop for SecretKey {
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

impl SecretKey {
    /// Generate an "unbiased" `SecretKey` directly from a user
    /// suplied `csprng` uniformly, bypassing the `MiniSecretKey`
    /// layer.
    pub fn from_rng<R>(rng: &mut R) -> Self
    where R: CryptoRng + RngCore,
    {
        let mut nonce_seed: [u8; 32] = [0u8; 32];
        rng.fill_bytes(&mut nonce_seed);
        let key = <jubjub::Scalar as ::ff::Field>::random(rng);
        let public = PublicKey::from_secret_scalar(&key);
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
    pub fn as_publickey(&self) -> &PublicKey { &self.public }

    /// Clone the `PublicKey` corresponding to this `SecretKey`.
    pub fn to_public(&self) -> PublicKey { self.public.clone() }
}
// TODO:  Convert to/from zcash_primitives::redjubjub::PrivateKey

impl ReadWrite for SecretKey  {
    fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let key = crate::read_scalar::<&mut R>(&mut reader) ?;
        let mut nonce_seed = [0u8; 32];
        reader.read_exact(&mut nonce_seed) ?;
        let public = PublicKey::from_secret_scalar(&key);
        Ok(SecretKey { key, nonce_seed, public, } )
    }

    fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        crate::write_scalar::<&mut W>(&self.key, &mut writer) ?;
        writer.write_all(&self.nonce_seed) ?;
        Ok(())
    }
}

