// Copyright (c) 2022-2023 Web 3 Foundation

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod ring;
pub mod zcash_consts;

use ark_ff::MontFp;
use ark_ec::{
    AffineRepr, CurveGroup
    // hashing::{HashToCurveError, curve_maps, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
};
use ark_std::vec::Vec;   // io::{Read, Write}

pub use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, SerializationError, Compress};

#[cfg(not(feature = "substrate-curves"))]
mod curves {
    pub use ark_ed_on_bls12_381_bandersnatch as bandersnatch;
    pub use ark_bls12_381 as bls12_381;
}
#[cfg(feature = "substrate-curves")]
mod curves {
    pub use sp_ark_ed_on_bls12_381_bandersnatch as bandersnatch;
    pub use sp_ark_bls12_381 as bls12_381;
}
pub use curves::*;

#[cfg(feature = "tiny-compress")]
mod affine;
#[cfg(feature = "tiny-compress")]
mod affine_defs {
    use super::*;
    pub use affine::{BandersnatchAffine, BandersnatchConfig, COMPRESSED_POINT_SIZE};
}
#[cfg(not(feature = "tiny-compress"))]
mod affine_defs {
    use super::*;
    pub use bandersnatch::{BandersnatchConfig, SWAffine as BandersnatchAffine};
    pub const COMPRESSED_POINT_SIZE: usize = 33;
}
use affine_defs::*;

// Conversion discussed in https://github.com/arkworks-rs/curves/pull/76#issuecomment-929121470

pub use dleq_vrf::{
    Transcript, IntoTranscript, transcript,
    error::{SignatureResult, SignatureError},
    vrf::{self, IntoVrfInput},
    EcVrfSecret,EcVrfSigner,EcVrfVerifier,
    VrfSignature,VrfSignatureVec,
    scale,
};

pub type VrfInput = dleq_vrf::vrf::VrfInput<BandersnatchAffine>;
pub type VrfPreOut = dleq_vrf::vrf::VrfPreOut<BandersnatchAffine>;
pub type VrfInOut = dleq_vrf::vrf::VrfInOut<BandersnatchAffine>;

pub struct Message<'a> {
    pub domain: &'a [u8],
    pub message: &'a [u8],
}

/*
type H2C = MapToCurveBasedHasher::<
G1Projective,
    DefaultFieldHasher<sha2::Sha256>,
    curve_maps::wb::WBMap<curve::g1::Config>,
>;

pub fn hash_to_bandersnatch_curve(domain: &[u8],message: &[u8]) -> Result<VrfInput,HashToCurveError> {
    dleq_vrf::vrf::ark_hash_to_curve::<Jubjub,H2C>(domain,message)
}
*/

impl<'a> IntoVrfInput<BandersnatchAffine> for Message<'a> {
    fn into_vrf_input(self) -> VrfInput {
        // TODO: Add Elligator to Arkworks
        // hash_to_bandersnatch_curve(self.domain,self.message)
        // .expect("Hash-to-curve error, IRTF spec forbids messages longer than 2^16!")
        let label = b"TemporaryDoNotDeploy".as_ref();
        let mut t = Transcript::new_labeled(label);
        t.label(b"domain");
        t.append(self.domain);
        t.label(b"message");
        t.append(self.message);
        let p: <BandersnatchAffine as AffineRepr>::Group = t.challenge(b"vrf-input").read_uniform();
        vrf::VrfInput( p.into_affine() )
    }
}

pub const BLINDING_BASE: BandersnatchAffine = {
    const X: bandersnatch::Fq = MontFp!("4956610287995045830459834427365747411162584416641336688940534788579455781570");
    const Y: bandersnatch::Fq = MontFp!("52360910621642801549936840538960627498114783432181489929217988668068368626761");
    BandersnatchAffine::new_unchecked(X, Y)
};


type ThinVrf = dleq_vrf::ThinVrf<BandersnatchAffine>;

/// Then VRF configured by the G1 generator for signatures.
pub fn thin_vrf() -> ThinVrf {
    dleq_vrf::ThinVrf::default()  //  keying_base: Jubjub::generator()
}

type PedersenVrf = dleq_vrf::PedersenVrf<BandersnatchAffine>;

/// Pedersen VRF configured by the G1 generator for public key certs.
pub fn pedersen_vrf() -> PedersenVrf {
    thin_vrf().pedersen_vrf([ BLINDING_BASE ])
}


pub type SecretKey = dleq_vrf::SecretKey<BandersnatchAffine>;

pub const PUBLIC_KEY_LENGTH: usize = COMPRESSED_POINT_SIZE;
pub type PublicKeyBytes = [u8; PUBLIC_KEY_LENGTH];

pub type PublicKey = dleq_vrf::PublicKey<BandersnatchAffine>;

type ThinVrfProof = dleq_vrf::Batchable<ThinVrf>;

pub type ThinVrfSignature<const N: usize> = dleq_vrf::VrfSignature<ThinVrfProof,N>;


type PedersenVrfProof = dleq_vrf::Batchable<PedersenVrf>;

#[derive(Clone,CanonicalSerialize,CanonicalDeserialize)]
pub struct RingVrfProof {
    pub dleq_proof: PedersenVrfProof,
    pub ring_proof: ring::RingProof,
}

impl dleq_vrf::EcVrfProof for RingVrfProof {
    type H = BandersnatchAffine;
}

// TODO: Can you impl Debug+Eq+PartialEq for ring::RingProof please Sergey?  We'll then derive Debug.
mod tmp {
    use ark_std::fmt::{Debug,Formatter,Error};
    impl Debug for crate::RingVrfProof {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
            self.dleq_proof.fmt(f)
        }
    }
    impl Eq for crate::RingVrfProof {}
    impl PartialEq for crate::RingVrfProof {
        fn eq(&self, other: &Self) -> bool {
            // Ignore ring_proof for now
            self.dleq_proof == other.dleq_proof
        }
    }
}

impl scale::ArkScaleMaxEncodedLen for RingVrfProof {
    fn max_encoded_len(compress: Compress) -> usize {
        <PedersenVrfProof as scale::ArkScaleMaxEncodedLen>::max_encoded_len(compress)
        + 4096  // TODO: How large is RingProof, Sergey?
    }
}

// TODO: Sergey, should this be #[derive(Debug,Clone)] ?
pub struct RingVerifier<'a>(pub &'a ring::RingVerifier);

pub type RingVrfSignature<const N: usize> = dleq_vrf::VrfSignature<RingVrfProof,N>;

impl EcVrfVerifier for RingVerifier<'_> {
    type Proof = RingVrfProof;
    type Error = SignatureError;

    fn vrf_verify_detached<'a>(
        &self,
        t: impl IntoTranscript,
        ios: &'a [VrfInOut],
        signature: &RingVrfProof,
    ) -> Result<&'a [VrfInOut],Self::Error> {
        let ring_verifier = &self.0;
        pedersen_vrf().verify_pedersen_vrf(t,ios.as_ref(),&signature.dleq_proof) ?;

        let key_commitment = signature.dleq_proof.as_key_commitment();
        match ring_verifier.verify_ring_proof(signature.ring_proof.clone(), key_commitment.0.clone()) {
            true => Ok(ios),
            false => Err(SignatureError::Invalid),
        }
    }
}

impl RingVerifier<'_> {
    pub fn verify_ring_vrf<const N: usize>(
        &self,
        t: impl IntoTranscript,
        inputs: impl IntoIterator<Item = impl IntoVrfInput<BandersnatchAffine>>,
        signature: &RingVrfSignature<N>,
    ) -> Result<[VrfInOut; N],SignatureError>
    {
        self.vrf_verify(t, inputs, signature)
    }
}


// #[derive(Clone)]
pub struct RingProver<'a> {
    pub ring_prover: &'a ring::RingProver,
    pub secret: &'a SecretKey,
}

impl<'a> core::borrow::Borrow<SecretKey> for RingProver<'a> {
    fn borrow(&self) -> &SecretKey { &self.secret }
}

impl<'a> EcVrfSigner for RingProver<'a> {
    type Proof = RingVrfProof;
    type Error = ();
    type Secret = SecretKey;
    fn vrf_sign_detached(
        &self,
        t: impl IntoTranscript,
        ios: &[VrfInOut]
    ) -> Result<RingVrfProof,()>
    {
        let RingProver { ring_prover, secret } = *self;
        let secret_blinding = None; // TODO: Set this first so we can hash the ring proof
        let (dleq_proof,secret_blinding) = pedersen_vrf().sign_pedersen_vrf(t, ios, secret_blinding, secret);
        let ring_proof = ring_prover.prove(secret_blinding.0[0]);
        Ok(RingVrfProof { dleq_proof, ring_proof, })
    }
}

impl<'a> RingProver<'a> {
    pub fn sign_ring_vrf<const N: usize>(
        &self,
        t: impl IntoTranscript,
        ios: &[VrfInOut; N],
    ) -> RingVrfSignature<N>
    {
        self.vrf_sign(t, ios).expect("no failure modes")
    }
}


// TODO:  Run test vector tests once we have some even without getrandom
// #[cfg(test)]
// mod testvectors {
// }

#[cfg(all(test, feature = "getrandom"))]
mod tests {
    use super::*;
    use ark_std::rand::RngCore;
    use std::iter;
    use dleq_vrf::scale::{ArkScale, ArkScaleRef, ArkScaleMaxEncodedLen, Decode, Encode, MaxEncodedLen};

    #[test]
    fn check_blinding_base() {
        let mut t = b"Bandersnatch VRF blinding base".into_transcript();
        let blinding_base: <BandersnatchAffine as AffineRepr>::Group = t.challenge(b"vrf-input").read_uniform();
        debug_assert_eq!(blinding_base.into_affine(), BLINDING_BASE);
    }

    #[test]
    fn good_max_encoded_len() {
        use dleq_vrf::scale::MaxEncodedLen;
        assert_eq!(crate::PUBLIC_KEY_LENGTH, <PublicKey as MaxEncodedLen>::max_encoded_len());
    }

    #[test]
    fn thin_sign_verify() {
        let secret = SecretKey::from_seed(&[0; 32]);
        let public = secret.to_public();
        assert_eq!(public.compressed_size(), PUBLIC_KEY_LENGTH);

        let input = Message {
            domain: b"domain",
            message: b"message",
        }.into_vrf_input();
        let io = secret.vrf_inout(input.clone());
        let transcript = Transcript::new_labeled(b"label");

        let signature: ThinVrfSignature<1> = secret.sign_thin_vrf(transcript.clone(), &[io.clone()]);

        let result = public.verify_thin_vrf(transcript, iter::once(input), &signature);
        
        assert!(result.is_ok());
        let io2 = result.unwrap();
        assert_eq!(io2[0].preoutput, io.preoutput);
    }

    fn ring_test_init(pk: PublicKey) -> (ring::RingProver, ring::RingVerifier) {
        use ark_std::UniformRand;

        let kzg = ring::KZG::testing_kzg_setup([0; 32], 2u32.pow(10));
        let keyset_size = kzg.max_keyset_size();

        let mut rng = rand_core::OsRng;
		let mut l = [0u8; 8];
		rng.fill_bytes(&mut l);
		let keyset_size = usize::from_le_bytes(l) % keyset_size;

        // Gen a bunch of random public keys
        let mut pks: Vec<_> = (0..keyset_size).map(|_| BandersnatchAffine::rand(&mut rng)).collect();
        // Just select one index for the actual key we are for signing
        let secret_key_idx = keyset_size / 2;
        pks[secret_key_idx] = pk.0.into();

        let prover_key = kzg.prover_key(pks.clone());
        let ring_prover = kzg.init_ring_prover(prover_key, secret_key_idx);

        let verifier_key = kzg.verifier_key(pks);
        let ring_verifier = kzg.init_ring_verifier(verifier_key);

        (ring_prover, ring_verifier)
    }

    #[test]
    fn ring_sign_verify() {
        #[cfg(feature = "tiny-compress")]
        const RING_PROOF_SIZE: usize = 752;
        #[cfg(not(feature = "tiny-compress"))]
        const RING_PROOF_SIZE: usize = 755;

        let secret = &SecretKey::from_seed(&[0; 32]);

        let (ring_prover, ring_verifier) = ring_test_init(secret.to_public());
        
        let input = Message { domain: b"domain", message: b"message"}.into_vrf_input();
        let io = secret.vrf_inout(input.clone());
        let transcript: &[u8] = b"Meow";  // Transcript::new_labeled(b"label");
        
        let signature: RingVrfSignature<1> = RingProver {
            ring_prover: &ring_prover, secret,
        }.sign_ring_vrf(transcript, &[io]);
        assert_eq!(signature.proof.compressed_size(), RING_PROOF_SIZE);
        assert_eq!(signature.compressed_size(), RING_PROOF_SIZE + COMPRESSED_POINT_SIZE);
        let mut buf = [0u8; RING_PROOF_SIZE + COMPRESSED_POINT_SIZE];
        signature.serialize_compressed(&mut buf[..]).unwrap();
        let signature2 = RingVrfSignature::<1>::deserialize_compressed(&buf[..]).unwrap();
        assert_eq!(signature, signature2);
        
        let result = RingVerifier(&ring_verifier)
            .verify_ring_vrf(transcript, iter::once(input), &signature);
        assert!(result.is_ok());
    }

    const SCALAR_SIZE: usize = 32;

    #[test]
    fn serialization_works() {
        let secret = &SecretKey::from_seed(&[0; 32]);
        let mut buf = [0u8; 128];

        let public1 = secret.to_public();
        assert_eq!(public1.compressed_size(), COMPRESSED_POINT_SIZE);
        public1.serialize_compressed(&mut buf[..COMPRESSED_POINT_SIZE]).unwrap();
        let public2 = PublicKey::deserialize_compressed(&buf[..COMPRESSED_POINT_SIZE]).unwrap();
        assert_eq!(public1, public2);

        let input = Message { domain: b"domain", message: b"message"}.into_vrf_input();
        input.serialize_compressed(&mut buf[..COMPRESSED_POINT_SIZE]).unwrap();
        let input2 = VrfInput::deserialize_compressed(&buf[..COMPRESSED_POINT_SIZE]).unwrap();
        assert_eq!(input, input2);
        
        let io = secret.vrf_inout(input.clone());
        io.serialize_compressed(&mut buf[..2*COMPRESSED_POINT_SIZE]).unwrap();
        let io2 = VrfInOut::deserialize_compressed(&buf[..2*COMPRESSED_POINT_SIZE]).unwrap();
        assert_eq!(io, io2);
       
        let transcript = Transcript::new_labeled(b"label");
        let signature: ThinVrfSignature<1> = secret.sign_thin_vrf(transcript.clone(), &[io.clone()]);
        assert_eq!(signature.compressed_size(), 2 * COMPRESSED_POINT_SIZE + SCALAR_SIZE);
        assert_eq!(signature.proof.compressed_size(), COMPRESSED_POINT_SIZE + SCALAR_SIZE);
        assert_eq!(signature.preouts[0].compressed_size(), COMPRESSED_POINT_SIZE);
        signature.serialize_compressed(&mut buf[..3*COMPRESSED_POINT_SIZE]).unwrap();
        let signature2 = ThinVrfSignature::<1>::deserialize_compressed(&buf[..3*COMPRESSED_POINT_SIZE]).unwrap();
        assert_eq!(signature, signature2);
    }

    #[test]
    fn ark_scale_works() {
        let secret = &SecretKey::from_seed(&[0; 32]);

        let public1 = secret.to_public();
        assert_eq!(<PublicKey as ArkScaleMaxEncodedLen>::max_encoded_len(Compress::Yes), COMPRESSED_POINT_SIZE);
        assert_eq!(<PublicKey as MaxEncodedLen>::max_encoded_len(), COMPRESSED_POINT_SIZE);
        assert_eq!(public1.encoded_size(), COMPRESSED_POINT_SIZE);
        let bytes = public1.encode();
        assert_eq!(bytes.len(), COMPRESSED_POINT_SIZE);
        let public2 = PublicKey::decode(&mut bytes.as_slice()).unwrap();
        assert_eq!(public1, public2);
       
        let wrapped1 = ArkScale::<PublicKey>::from(public1);
        assert_eq!(wrapped1.encode(), bytes);
        let wrapped2 = ArkScale::<PublicKey>::decode(&mut bytes.as_slice()).unwrap();
        assert_eq!(wrapped1, wrapped2);

        let wrapped_ref: ArkScaleRef<PublicKey> = ArkScaleRef(&public2);
        assert_eq!(wrapped_ref.encode(), bytes);
    }
}
