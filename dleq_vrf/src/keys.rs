// Copyright (c) 2019-2020 Web 3 Foundation

//! ### VRF keys

// use core::fmt::{Debug};

use core::ops::{Add,AddAssign,Mul,MulAssign};

use ark_ff::fields::{PrimeField}; // Field
use ark_std::{UniformRand, vec::Vec, io::{Read, Write}};
use ark_ec::{AffineRepr, Group}; // CurveGroup
use ark_serialize::{CanonicalSerialize,CanonicalDeserialize,SerializationError};

// use subtle::{Choice,ConstantTimeEq};
use rand_core::{RngCore,CryptoRng};

use zeroize::Zeroize;

use crate::{ThinVrf};


/// Public key
#[derive(Debug,Clone,Eq,Hash,CanonicalSerialize,CanonicalDeserialize)] // Copy, PartialOrd, Ord, Hash, 
pub struct PublicKey<C: AffineRepr>(pub C);

impl<C: AffineRepr> PartialEq for PublicKey<C> {
    fn eq(&self, other: &PublicKey<C>) -> bool {
        crate::eq_mod_small_cofactor_affine(&self.0, &other.0)
    }
}

/// Arkworks' own serialization traits should be preferred over these.
impl<C: AffineRepr> PublicKey<C> {
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


/*
pub(crate) fn fake_secret_pair_from_rng<F: PrimeField> (rng: impl RngCore+CryptoRng) -> F {
    <F as UniformRand>::rand(&mut rng) + <F as UniformRand>::rand(&mut rng)
}
*/

/// Secret scalar split into two scalars.  Incurs 2x penalty in scalar multiplications. 
#[derive(Clone,PartialEq,Eq)] // Copy, CanonicalSerialize,CanonicalDeserialize, Hash, 
pub(crate) struct SecretPair<F: PrimeField>(pub(crate) [F; 2]);

impl<F: PrimeField> Zeroize for SecretPair<F> { 
    fn zeroize(&mut self) { self.0.zeroize(); }
}
impl<F: PrimeField> Drop for SecretPair<F> {
    fn drop(&mut self) { self.zeroize() }
}

impl<F: PrimeField> SecretPair<F> {
    /// Initialize and unbiased `SecretPair` from a `CryptoRng`,
    /// deterministic assuming `CryptoRng` is.
    pub fn from_rng<R: RngCore+CryptoRng>(rng: &mut R) -> Self {
        // It's frankly obnoxious that arkworks uses rand here, not just rand_core.
        SecretPair([
            <F as UniformRand>::rand(rng), 
            <F as UniformRand>::rand(rng)
        ])
    }

    pub fn resplit(&mut self) {
        let x = <F as UniformRand>::rand( &mut crate::transcript::getrandom_or_panic() );
        self.0[0] += &x;
        self.0[1] -= &x;
    }

    /// Multiply by a scalar.
    pub fn mul_by_challenge(&mut self, rhs: &F) -> F {
        let mut lhs = self.clone();
        lhs *= rhs;
        lhs.0[0] + lhs.0[1]
    }

    /// Arkworks multiplies on the right since ark_ff is a dependency of ark_ec.
    /// but ark_ec being our dependency requires left multiplication here.
    fn mul_action<G: Group<ScalarField=F>>(&self, x: &mut G) {
        let mut y = x.clone();
        *x *= self.0[0];
        y *= self.0[1];
        *x += y;
    }
}

impl<F: PrimeField> MulAssign<&F> for SecretPair<F> {
    /// Multiply by a scalar, guts of `mul_by_challenge`.
    /// Invokes `replit` so do manually for witnesses.
    fn mul_assign(&mut self, rhs: &F) {
        self.0[0] *= rhs;
        self.0[1] *= rhs;
        self.resplit();
    }
}

impl<F: PrimeField> AddAssign<&SecretPair<F>> for SecretPair<F> {
    fn add_assign(&mut self, rhs: &SecretPair<F>) {
        self.0[0] += rhs.0[0];
        self.0[1] += rhs.0[1];
    }
}
impl<F: PrimeField> Add<&SecretPair<F>> for &SecretPair<F> {
    type Output = SecretPair<F>;
    fn add(self, rhs: &SecretPair<F>) -> SecretPair<F> {
        let mut lhs = self.clone();
        lhs += rhs;
        lhs
    }
}
/*
impl<G: Group> Mul<&G> for &SecretPair<<G as Group>::ScalarField> {
    type Output = G;
    /// Arkworks multiplies on the right since ark_ff is a dependency of ark_ec.
    /// but ark_ec being our dependency requires left multiplication here.
    fn mul(self, rhs: &G) -> G {
        let mut rhs = rhs.clone();
        self.mul_action(&mut rhs);
        rhs
    }
}
*/
impl<C: AffineRepr> Mul<&C> for &mut SecretPair<<C as AffineRepr>::ScalarField> {
    type Output = <C as AffineRepr>::Group;
    /// Arkworks multiplies on the right since ark_ff is a dependency of ark_ec.
    /// but ark_ec being our dependency requires left multiplication here.
    fn mul(self, rhs: &C) -> Self::Output {
        let o = rhs.mul(self.0[0]) + rhs.mul(self.0[1]);
        use ark_ec::CurveGroup;
        debug_assert_eq!(o.into_affine(), { let mut t = rhs.into_group(); self.mul_action(&mut t); t }.into_affine() );
        self.resplit();
        o
    }
}


/// Length of the nonce seed accompanying the secret key.
pub const NONCE_SEED_LENGTH: usize = 32;


/// Seceret key consisting of a scalar and a secret nonce seed.
#[derive(Clone)]
pub struct SecretKey<K: AffineRepr> {
    /// Specify keying base point by a Thin VRF flavor
    /// 
    /// Remark:  We'd have slightly nicer flow in the signing methods
    /// of `PedersenVrf` if we made this a polymorphic `F: Flavor`.
    /// We cannot easily be polymorphic over borrowing inside
    /// structs though, so doing this breaks signing `ThinVrf`s
    /// and `PedersenVrf`s using the same secret key.
    pub(crate) thin: ThinVrf<K>,

    /// Secret key represented as a scalar.
    pub(crate) key: SecretPair<<K as AffineRepr>::ScalarField>,

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
    public: PublicKey<K>,
}

impl<K: AffineRepr> Zeroize for SecretKey<K> {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.nonce_seed.zeroize();
    }
}
impl<K: AffineRepr> Drop for SecretKey<K> {
    fn drop(&mut self) { self.zeroize() }
}

/*
impl<K: AffineRepr> Debug for SecretKey<K> {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "SecretKey {{ key: {:?} nonce: {:?} }}", &self.key, &self.nonce)
    }
}

impl<K: AffineRepr> Eq for SecretKey<K> {}
impl<K: AffineRepr> PartialEq for SecretKey<K> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).unwrap_u8() == 1u8
    }
}
impl<K: AffineRepr> ConstantTimeEq for SecretKey<K> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.key.ct_eq(&other.key)
    }
}
*/


impl<K: AffineRepr> SecretKey<K> {
    /// Generate an "unbiased" `SecretKey` from a user supplied
    /// `CryptoRng`, deterministic assuming the `CryptoRng` is.
    pub fn from_rng<R>(thin: ThinVrf<K>, rng: &mut R) -> Self
    where R: CryptoRng + RngCore,
    {
        let mut nonce_seed: [u8; 32] = [0u8; 32];
        rng.fill_bytes(&mut nonce_seed);
        let mut key = SecretPair::from_rng(rng);
        let public = thin.make_public(&mut key);
        SecretKey { thin, key, nonce_seed, public, }
    }

    /// Generate a `SecretKey` from a 32 byte seed.
    pub fn from_seed(thin: ThinVrf<K>, seed: [u8; 32]) -> Self {
        use rand_core::SeedableRng;
        let mut rng = ::rand_chacha::ChaChaRng::from_seed(seed);
        SecretKey::from_rng(thin, &mut rng)
    }

    /// Generate an ephemeral `SecretKey` with system randomness.
    #[cfg(feature = "getrandom")]
    pub fn ephemeral(thin: ThinVrf<K>) -> Self {
        SecretKey::from_rng(thin, &mut ::rand_core::OsRng)
    }

    /// Reference the `PublicKey` corresponding to this `SecretKey`.
    pub fn as_publickey(&self) -> &PublicKey<K> { &self.public }

    /// Clone the `PublicKey` corresponding to this `SecretKey`.
    pub fn to_public(&self) -> PublicKey<K> { self.public.clone() }

/*
    #[inline]
    pub fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        writer.write_all(&self.nonce_seed) ?;
        self.key.0[0].serialize_compressed(writer)
        self.key.0[1].serialize_compressed(writer)
    }

    #[inline]
    pub fn serialized_size(&self) -> usize {
        NONCE_SEED_LENGTH + 2 * self.key.compressed_size()
    }

    #[inline]
    pub fn deserialize<R: Read>(thin: ThinVrf<K>, mut reader: R) -> Result<Self, SerializationError> {
        let mut nonce_seed = [0u8; 32];
        reader.read_exact(&mut nonce_seed) ?;
        let key = SecretPair([
            <K as AffineRepr>::ScalarField::deserialize_compressed(&mut reader) ?,
            <K as AffineRepr>::ScalarField::deserialize_compressed(&mut reader) ?
        ])
        let public = thin.make_public(&key);
        Ok(SecretKey { thin, key, nonce_seed, public, })
 
   }
*/

}
// TODO:  Convert to/from zcash_primitives::redjubjub::PrivateKey

