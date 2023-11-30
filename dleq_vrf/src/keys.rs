// Copyright (c) 2019-2020 Web 3 Foundation

//! ### VRF keys


use zeroize::Zeroize;

use ark_std::{vec::Vec, io::{Read, Write}};
// #[cfg(debug_assertions)]
// use ark_std::{boxed::Box, sync::Mutex};

use ark_ec::{AffineRepr}; // Group, CurveGroup
use ark_serialize::{CanonicalSerialize,CanonicalDeserialize,SerializationError};

#[cfg(feature = "getrandom")]
use ark_secret_scalar::{rand_core, RngCore};

use ark_secret_scalar::SecretScalar;

use crate::{
    ThinVrf,
    transcript::digest::{Update,XofReader},

};


/// Public key
#[derive(Debug,Clone,Eq,Hash,CanonicalSerialize,CanonicalDeserialize)] // Copy, PartialOrd, Ord, Hash, 
#[repr(transparent)]
pub struct PublicKey<C: AffineRepr>(pub C);

impl<C: AffineRepr> PartialEq for PublicKey<C> {
    fn eq(&self, other: &PublicKey<C>) -> bool {
        crate::zero_mod_small_cofactor(self.0.into_group() - other.0.into_group())
    }
}

/// Arkworks' own serialization traits should be preferred over these.
impl<C: AffineRepr> PublicKey<C> {
    pub fn update_digest(&self, h: &mut impl Update) {
        // This private struct works around Serialize taking the pre-existing
        // std::io::Write instance of most digest::Digest implementations by value
        struct HashMarshaller<'a, H: Update>(&'a mut H);
        impl<'a, H: Update> ark_std::io::Write for HashMarshaller<'a, H> {
            #[inline]
            fn write(&mut self, buf: &[u8]) -> ark_std::io::Result<usize> {
                Update::update(self.0, buf);
                Ok(buf.len())
            }
            #[inline]
            fn flush(&mut self) -> ark_std::io::Result<()> {
                Ok(())
            }
        }
        self.0.serialize_compressed(HashMarshaller(h)).unwrap();
    }

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
    pub(crate) key: SecretScalar<<K as AffineRepr>::ScalarField>,

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

    #[cfg(debug_assertions)]
    test_vector_fake_rng: bool,

    // #[cfg(debug_assertions)]
    // rng: Option<Mutex<Box<dyn RngCore+CryptoRng+Send>>>,
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

impl<K: AffineRepr> ThinVrf<K> {
    /// Generate an "unbiased" `SecretKey` from a user supplied `XofReader`.
    pub fn secretkey_from_xof(self, mut xof: impl XofReader) -> SecretKey<K>
    {
        let mut nonce_seed: [u8; 32] = [0u8; 32];
        xof.read(&mut nonce_seed);
        let mut key = SecretScalar::from_xof(&mut xof);
        let public = self.make_public(&mut key);
        SecretKey { thin: self, key, nonce_seed, public, 
            #[cfg(debug_assertions)]
            test_vector_fake_rng: false,
        }
    }

    /// Generate a `SecretKey` from a 32 byte seed.
    pub fn secretkey_from_seed(self, seed: &[u8; 32]) -> SecretKey<K> {
        use crate::transcript::digest::{ExtendableOutput};
        let mut xof = crate::transcript::Shake128::default();
        xof.update(b"VrfSecretSeed");
        xof.update(seed.as_ref());
        xof.update(& (32u32).to_be_bytes());
        xof.update(b"VrfSecretKey");
        self.secretkey_from_xof(xof.finalize_xof())
    }

    /// Generate an ephemeral `SecretKey` with system randomness.
    #[cfg(feature = "getrandom")]
    pub fn ephemeral_secretkey(self) -> SecretKey<K> {
        let mut seed: [u8; 32] = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        self.secretkey_from_seed(&seed)
    }
}
// 
impl<K: AffineRepr> SecretKey<K> {
    /// Generate an "unbiased" `SecretKey` from a user supplied `XofReader`.
    pub fn from_xof(xof: impl XofReader) -> Self
    {
        ThinVrf::<K>::default().secretkey_from_xof(xof)
    }

    /// Generate a `SecretKey` from a 32 byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        ThinVrf::<K>::default().secretkey_from_seed(seed)
    }

    /// Generate an ephemeral `SecretKey` with system randomness.
    #[cfg(feature = "getrandom")]
    pub fn ephemeral() -> Self {
         ThinVrf::<K>::default().ephemeral_secretkey()
    }

    /// Reference the `PublicKey` corresponding to this `SecretKey`.
    pub fn as_publickey(&self) -> &PublicKey<K> { &self.public }

    /// Clone the `PublicKey` corresponding to this `SecretKey`.
    pub fn to_public(&self) -> PublicKey<K> { self.public.clone() }

    // #[cfg(debug_assertions)]
    // pub fn set_rng(&mut self, rng: &Box<dyn RngCore+CryptoRng>) {
    //     self.rng = Some(Mutex::new(rng));
    // }

    #[cfg(debug_assertions)]
    pub fn set_rng_for_test_vectors(&mut self) {
        self.test_vector_fake_rng = true;
        // transcript::tests::TestVectorFakeRng
    }

    pub fn witness(&self, t: &crate::Transcript, label: impl ark_transcript::AsLabel) -> ark_transcript::Reader {
        let mut t = t.fork(b"witness");
        t.label(label);
        t.append(&self.nonce_seed[..]);
        #[cfg(debug_assertions)]
        if self.test_vector_fake_rng {
            return t.witness(&mut ark_transcript::debug::TestVectorFakeRng);

        }
        // #[cfg(debug_assertions)]
        // if let Some(rng) = self.rng {
        //     if let Ok(rng) = rng.lock() {
        //         return t.witness(rng.deref_mut());
        //     }
        // }
        t.witness(&mut ark_secret_scalar::getrandom_or_panic())
    }

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
        let key = SecretScalar([
            <K as AffineRepr>::ScalarField::deserialize_compressed(&mut reader) ?,
            <K as AffineRepr>::ScalarField::deserialize_compressed(&mut reader) ?
        ])
        let public = thin.make_public(&key);
        Ok(SecretKey { thin, key, nonce_seed, public, })
 
   }
*/
}

