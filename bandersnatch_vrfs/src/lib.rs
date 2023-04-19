// Copyright (c) 2022-2023 Web 3 Foundation

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![doc = include_str!("../README.md")]


use rand_core::{CryptoRng, RngCore};

use ark_ec::{
    AffineRepr, CurveGroup,
    hashing::{HashToCurveError, curve_maps, map_to_curve_hasher::MapToCurveBasedHasher}, // HashToCurve
};
use ark_serialize::{CanonicalSerialize,CanonicalDeserialize};  // SerializationError
use ark_std::{ borrow::BorrowMut, Zero, vec::Vec, };   // io::{Read, Write}

pub use ark_ed_on_bls12_381_bandersnatch::{
    self as bandersnatch,
    EdwardsAffine,
};

pub use dleq_vrf::{
    Transcript, IntoTranscript,
    error::{SignatureResult, SignatureError},
    vrf::{self, IntoVrfInput},
};

use bandersnatch::{
    EdwardsAffine as E,
};

pub type VrfInput = dleq_vrf::vrf::VrfInput<E>;
pub type VrfPreOut = dleq_vrf::vrf::VrfPreOut<E>;
pub type VrfInOut = dleq_vrf::vrf::VrfInOut<E>;

#[cfg(test)]
mod tests;


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
        use ark_std::UniformRand;
        let label = b"TemporaryDoNotDeploy".as_ref();
        let mut t = Transcript::new(label);
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
pub fn pedersen_vrf() -> PedersenVrf {
    let blinding_base = unimplemented!();
    dleq_vrf::PedersenVrf::new( E::generator(), [ blinding_base ] )
}


#[derive(Clone)]  // Zeroize
pub struct SecretKey(pub dleq_vrf::SecretKey<E>);

impl SecretKey {
    /// Generate an ephemeral `SecretKey` with system randomness.
    #[cfg(feature = "getrandom")]
    pub fn ephemeral() -> Self {
        Self(dleq_vrf::SecretKey::ephemeral(thin_vrf()))
    }

    /// Generate a `SecretKey` from a 32 byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        SecretKey( dleq_vrf::SecretKey::from_seed( thin_vrf(), seed ))
    }

    pub fn to_public(&self) -> PublicKey { 
        PublicKey( self.0.to_public() )
    }

    pub fn sign_thin_vrf<const N: usize>(
        &mut self,
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
        &mut self,
        t: impl IntoTranscript,
        ios: &[VrfInOut]
    ) -> RingVrfSignature<N>
    {
        assert_eq!(ios.len(), N);
        let (signature,secret_blinding) = pedersen_vrf().sign_pedersen_vrf(t, ios, None, &mut self.0);
        let preoutputs = vrf::collect_preoutputs_array(ios);
        let ring_proof = (); // uses secret_blinding
        RingVrfSignature { preoutputs, signature, ring_proof, }
    }
}


#[derive(Debug,Clone,CanonicalSerialize,CanonicalDeserialize)]
pub struct PublicKey(pub dleq_vrf::PublicKey<E>);


#[derive(Debug,Clone,CanonicalSerialize,CanonicalDeserialize)]
pub struct ThinVrfSignature<const N: usize> {
    signature: dleq_vrf::Signature<ThinVrf>,
    preoutputs: [VrfPreOut; N],
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


#[derive(Debug,Clone,CanonicalSerialize,CanonicalDeserialize)]
pub struct RingVrfSignature<const N: usize> {
    signature: dleq_vrf::Signature<PedersenVrf>,
    preoutputs: [VrfPreOut; N],
    ring_proof: (),
}

impl<const N: usize> RingVrfSignature<N>
{
    pub fn verify_ring_vrf<I,II>(
        &self,
        t: impl IntoTranscript,
        inputs: II,
    ) -> SignatureResult<[VrfInOut; N]>
    where
        I: IntoVrfInput<E>,
        II: IntoIterator<Item=I>,
    {
        let ios = vrf::attach_inputs_array(&self.preoutputs,inputs);
        pedersen_vrf().verify_pedersen_vrf(t,ios.as_ref(),&self.signature) ?;
        // self.ring_proof // uses self.signature.as_key_commitment()
        Ok(ios)
    }
}


