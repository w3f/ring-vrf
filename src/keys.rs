// Copyright (c) 2019-2020 Web 3 Foundation

//! ### Ring VRF keys

use std::io;
// use core::fmt::{Debug};

// use subtle::{Choice,ConstantTimeEq};
use rand_core::{RngCore,CryptoRng};

use zcash_primitives::jubjub::{
    JubjubEngine, // FixedGenerators, JubjubParams,
    edwards::Point, Unknown, // PrimeOrder
};

use zeroize::Zeroize;

use crate::{JubjubEngineWithParams, Scalar};


/// Public key consisting of a JubJub point
#[derive(Clone)] // Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash
pub struct PublicKey<E: JubjubEngine>(pub(crate) Point<E,Unknown>);

// serde_boilerplate!(PublicKey);

impl<E: JubjubEngineWithParams> PartialEq for PublicKey<E> {
    fn eq(&self, other: &PublicKey<E>) -> bool {
        let params = E::params();
        self.0.mul_by_cofactor(params) == other.0.mul_by_cofactor(params) 
    }
}
impl<E: JubjubEngineWithParams> Eq for PublicKey<E> { }


impl<E: JubjubEngineWithParams> PublicKey<E> {
    fn from_secret_scalar(secret: &Scalar<E>) -> PublicKey<E> {
        PublicKey( crate::scalar_times_generator(secret).into() )
    }
    
    pub fn read<R: io::Read>(reader: R) -> io::Result<Self> {
        Ok(PublicKey( Point::read(reader,E::params()) ? ))
    }

    pub fn write<W: io::Write>(&self, writer: W) -> io::Result<()> {
        self.0.write(writer)
    }

    pub fn blind(&self, blinding: Scalar<E>) -> BlindedPublicKey<E> {
        let params = E::params();
        let key = PublicKey( self.0.add(& crate::scalar_times_generator(&blinding).into(), params) );
        BlindedPublicKey { key, blinding, }
    }
}


/// Public key consisting of a JubJub point
#[derive(Clone)] // Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash
pub struct BlindedPublicKey<E: JubjubEngine> {
    pub(crate) key: PublicKey<E>,
    pub(crate) blinding: Scalar<E>,
}

impl<E: JubjubEngine> From<PublicKey<E>> for BlindedPublicKey<E> {
    fn from(key: PublicKey<E>) -> BlindedPublicKey<E> {
        use ff::Field;
        BlindedPublicKey { key, blinding: Scalar::<E>::zero(), }
    }
}

impl<E: JubjubEngineWithParams> BlindedPublicKey<E> {
    pub fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let blinding = crate::read_scalar::<E, &mut R>(&mut reader) ?;
        let key = PublicKey::read(reader) ?;
        Ok(BlindedPublicKey { key, blinding, })
    }

    pub fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        crate::write_scalar::<E, &mut W>(&self.blinding, &mut writer) ?;
        self.key.write(writer) ?;
        Ok(())
    }
}


/// Seceret key consisting of a JubJub scalar and a secret nonce seed.
#[derive(Clone)] // Debug
pub struct SecretKey<E: JubjubEngine> {
    /// Secret key represented as a scalar.
    pub(crate) key: Scalar<E>,

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
    public: PublicKey<E>,
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

impl<E: JubjubEngineWithParams> SecretKey<E> {
    /// Generate an "unbiased" `SecretKey` directly from a user
    /// suplied `csprng` uniformly, bypassing the `MiniSecretKey`
    /// layer.
    pub fn from_rng<R>(mut rng: R) -> SecretKey<E>
    where R: CryptoRng + RngCore,
    {
        let mut nonce_seed: [u8; 32] = [0u8; 32];
        rng.fill_bytes(&mut nonce_seed);
        let key = <E::Fs as ::ff::Field>::random(&mut rng);
        let public = PublicKey::from_secret_scalar(&key);
        SecretKey { key, nonce_seed, public, }
    }

    /// Generate a JubJub `SecretKey` from a 32 byte seed.
    pub fn from_seed(seed: [u8; 32]) -> SecretKey<E> {
        use rand_core::SeedableRng;
        let rng = ::rand_chacha::ChaChaRng::from_seed(seed);
        SecretKey::from_rng(rng)
    }

    /// Generate a JubJub `SecretKey` with the default randomness source.
    #[cfg(feature = "std")]
    pub fn new(params: &E::Params) -> SecretKey<E> {
        SecretKey::from_rng(::rand::thread_rng(), params)
    }

    /// Derive the `PublicKey` corresponding to this `SecretKey`.
    pub fn to_public(&self) -> PublicKey<E> {
        self.public.clone()
    }

    pub fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let key = crate::read_scalar::<E, &mut R>(&mut reader) ?;
        let mut nonce_seed = [0u8; 32];
        reader.read_exact(&mut nonce_seed) ?;
        let public = PublicKey::from_secret_scalar(&key);
        Ok(SecretKey { key, nonce_seed, public, } )
    }

    pub fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        crate::write_scalar::<E, &mut W>(&self.key, &mut writer) ?;
        writer.write_all(&self.nonce_seed) ?;
        Ok(())
    }

    // TODO:  Convert to/from zcash_primitives::redjubjub::PrivateKey
}

