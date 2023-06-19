// Copyright (c) 2022-2023 Web 3 Foundation

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod ring;

use zeroize::Zeroize;
use crate::ring::{RingProver, RingProof, RingVerifier};

use ark_ec::{
    AffineRepr, CurveGroup,
    hashing::{HashToCurveError, curve_maps, map_to_curve_hasher::MapToCurveBasedHasher}, // HashToCurve
};
use ark_std::{borrow::BorrowMut, Zero, vec::Vec, rand::RngCore};   // io::{Read, Write}

pub use ark_serialize::{CanonicalSerialize,CanonicalDeserialize};  // SerializationError

pub use ark_ed_on_bls12_381_bandersnatch::{
    self as bandersnatch,
    EdwardsAffine,
};
// Conversion discussed in https://github.com/arkworks-rs/curves/pull/76#issuecomment-929121470

pub use dleq_vrf::{
    Transcript, IntoTranscript, transcript,
    error::{SignatureResult, SignatureError},
    vrf::{self, IntoVrfInput},
};

// Set usage of SW affine form
// use bandersnatch::EdwardsAffine as E;
use bandersnatch::SWAffine as E;

pub type VrfInput = dleq_vrf::vrf::VrfInput<E>;
pub type VrfPreOut = dleq_vrf::vrf::VrfPreOut<E>;
pub type VrfInOut = dleq_vrf::vrf::VrfInOut<E>;

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
    dleq_vrf::vrf::ark_hash_to_curve::<E,H2C>(domain,message)
}
*/

impl<'a> IntoVrfInput<E> for Message<'a> {
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
        let p: <E as AffineRepr>::Group = t.challenge(b"vrf-input").read_uniform();
        vrf::VrfInput( p.into_affine() )
    }
}


type ThinVrf = dleq_vrf::ThinVrf<E>;

/// Then VRF configured by the G1 generator for signatures.
pub fn thin_vrf() -> ThinVrf {
    dleq_vrf::ThinVrf { keying_base: E::generator(), }
}

type PedersenVrf = dleq_vrf::PedersenVrf<E>;

/// Pedersen VRF configured by the G1 generator for public key certs.
pub fn pedersen_vrf(blinding_base: E) -> PedersenVrf {
    dleq_vrf::PedersenVrf::new( E::generator(), [ blinding_base ] )
}


#[derive(Clone,Zeroize)]
pub struct SecretKey(pub dleq_vrf::SecretKey<E>);

impl SecretKey {
    /// Generate an "unbiased" `SecretKey` from a user supplied `XofReader`.
    pub fn from_xof(xof: impl transcript::digest::XofReader) -> Self {
        SecretKey( dleq_vrf::SecretKey::from_xof( thin_vrf(), xof ))
    }

    /// Generate a `SecretKey` from a 32 byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        SecretKey( dleq_vrf::SecretKey::from_seed( thin_vrf(), seed ))
    }

    /// Generate an ephemeral `SecretKey` with system randomness.
    #[cfg(feature = "getrandom")]
    pub fn ephemeral() -> Self {
        use rand_core::OsRng;
        let mut seed: [u8; 32] = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        SecretKey::from_seed(&seed)
    }

    pub fn to_public(&self) -> PublicKey { 
        PublicKey( self.0.to_public() )
    }

    pub fn sign_thin_vrf<const N: usize>(
        &self,
        t: impl IntoTranscript,
        ios: &[VrfInOut]
    ) -> ThinVrfSignature<N>
    {
        assert_eq!(ios.len(), N);
        let signature = self.0.sign_thin_vrf(t,ios);
        let preoutputs = vrf::collect_preoutputs_array(ios);
        ThinVrfSignature { preoutputs, signature, }
    }

    pub fn sign_ring_vrf<const N: usize>(
        &self,
        t: impl IntoTranscript,
        ios: &[VrfInOut],
        ring_prover: &RingProver
    ) -> RingVrfSignature<N>
    {
        assert_eq!(ios.len(), N);
        let blinding_base = ring_prover.piop_params().h;
        let (signature,secret_blinding) = pedersen_vrf(blinding_base).sign_pedersen_vrf(t, ios, None, &self.0);
        let preoutputs = vrf::collect_preoutputs_array(ios);
        let ring_proof = ring_prover.prove(secret_blinding.0[0]);
        RingVrfSignature { preoutputs, signature, ring_proof, }
    }
}


#[derive(Debug,Clone,CanonicalSerialize,CanonicalDeserialize)]
pub struct PublicKey(pub dleq_vrf::PublicKey<E>);

#[derive(Debug,Clone,CanonicalSerialize,CanonicalDeserialize)]
pub struct ThinVrfSignature<const N: usize> {
    pub signature: dleq_vrf::Signature<ThinVrf>,
    pub preoutputs: [VrfPreOut; N],
}

impl<const N: usize> ThinVrfSignature<N>
{
    pub fn verify_thin_vrf<I,II>(
        &self,
        t: impl IntoTranscript,
        inputs: II,
        public: &PublicKey,
    ) -> SignatureResult<[VrfInOut; N]>
    where
        I: IntoVrfInput<E>,
        II: IntoIterator<Item=I>,
    {
        let ios = vrf::attach_inputs_array(&self.preoutputs,inputs);
        thin_vrf().verify_thin_vrf(t,ios.as_ref(),&public.0,&self.signature) ?;
        Ok(ios)
    }
}

pub type PedersenVrfSignature = dleq_vrf::Signature<PedersenVrf>;

#[derive(CanonicalSerialize,CanonicalDeserialize)]
pub struct RingVrfSignature<const N: usize> {
    pub signature: dleq_vrf::Signature<PedersenVrf>,
    pub preoutputs: [VrfPreOut; N],
    pub ring_proof: RingProof,
}

impl<const N: usize> RingVrfSignature<N>
{
    pub fn verify_ring_vrf<I,II>(
        &self,
        t: impl IntoTranscript,
        inputs: II,
        ring_verifier: &RingVerifier,
    ) -> SignatureResult<[VrfInOut; N]>
    where
        I: IntoVrfInput<E>,
        II: IntoIterator<Item=I>,
    {
        let ios = vrf::attach_inputs_array(&self.preoutputs,inputs);
        let blinding_base = ring_verifier.piop_params().h;
        pedersen_vrf(blinding_base).verify_pedersen_vrf(t,ios.as_ref(),&self.signature) ?;

        let key_commitment = self.signature.as_key_commitment();
        match ring_verifier.verify_ring_proof(self.ring_proof.clone(), key_commitment.0.clone()) {
            true => Ok(ios),
            false => Err(SignatureError::Invalid),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::iter;

    #[test]
    fn thin_sign_verify() {
        let secret = SecretKey::from_seed(&[0; 32]);
        let public = secret.to_public();

        let input = Message {
            domain: b"domain",
            message: b"message",
        }.into_vrf_input();
        let io = secret.0.vrf_inout(input.clone());
        let transcript = Transcript::new_labeled(b"label");

        let signature: ThinVrfSignature<1> = secret.sign_thin_vrf(transcript.clone(), &[io.clone()]);

        let result = signature.verify_thin_vrf(transcript, iter::once(input), &public);
        
        assert!(result.is_ok());
        let io2 = result.unwrap();
        assert_eq!(io2[0].preoutput, io.preoutput);
    }

    fn ring_test_init(pk: PublicKey) -> (RingProver, RingVerifier) {
        use ark_std::UniformRand;

        // TODO @jeff: WHAT EXACTILY IS THIS DOMAIN SIZE and what value should we use?
        let kzg = ring::KZG::testing_kzg_setup([0; 32], 2usize.pow(10));
        let keyset_size = kzg.max_keyset_size();

        // Gen a bunch of random public keys
        let mut rng = rand_core::OsRng;
        let mut pks: Vec<_> = (0..keyset_size).map(|_| E::rand(&mut rng)).collect();
        // Just select one spot for the actual key we are using
        let secret_key_idx = keyset_size / 2;
        pks[secret_key_idx] = pk.0.0.into();
     
        let prover_key = kzg.prover_key(pks.clone());
        let ring_prover = kzg.init_ring_prover(prover_key, secret_key_idx);

        let verifier_key = kzg.verifier_key(pks);
        let ring_verifier = kzg.init_ring_verifier(verifier_key);

        (ring_prover, ring_verifier)
    }

    #[test]
    fn ring_sign_verify() {
        let secret = SecretKey::from_seed(&[0; 32]);

        let (ring_prover, ring_verifier) = ring_test_init(secret.to_public());
        
        let input = Message {
            domain: b"domain",
            message: b"message",
        }.into_vrf_input();
        let io = secret.0.vrf_inout(input.clone());
        let transcript = Transcript::new_labeled(b"label");
        
        let signature: RingVrfSignature<1> = secret.sign_ring_vrf(transcript.clone(), &[io], &ring_prover);
        
        let result = signature.verify_ring_vrf(transcript, iter::once(input), &ring_verifier);
        assert!(result.is_ok());
    }
}
