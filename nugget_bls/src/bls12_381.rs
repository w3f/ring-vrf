
use ark_ff::fields::field_hashers::{DefaultFieldHasher};  // HashToField
use ark_ec::{
    AffineRepr, CurveGroup,
    pairing::{Pairing, prepare_g2, PairingOutput},
    hashing::{HashToCurve, HashToCurveError, curve_maps, map_to_curve_hasher::MapToCurveBasedHasher},
    bls12::Bls12Config,
};

use dleq_vrf::vrf::{VrfInput, IntoVrfInput};


pub use ark_bls12_381::{Bls12_381};
use ark_bls12_381::{G1Affine, G1Projective};

type H2C = MapToCurveBasedHasher::<
G1Projective,
    DefaultFieldHasher<sha2::Sha256>,
    curve_maps::wb::WBMap<ark_bls12_381::g1::Config>,
>;

pub fn hash_to_curve(domain: &[u8],message: &[u8]) -> Result<dleq_vrf::vrf::VrfInput<G1Affine>,HashToCurveError> {
    dleq_vrf::vrf::ark_hash_to_curve::<G1Affine,H2C>(domain,message)
}

pub struct Message<'a> {
    pub domain: &'a [u8],
    pub message: &'a [u8],
}

impl<'a> IntoVrfInput<G1Affine> for Message<'a> {
    fn into_vrf_input(self) -> VrfInput<G1Affine> {
        hash_to_curve(self.domain,self.message)
        .expect("Hash-to-curve error, IRTF spec forbids messages longer than 2^16!")
    }
}

pub type SecretKey = crate::SecretKey<Bls12_381>;
pub type PublicKey = crate::PublicKey<Bls12_381>;
pub type Signature = crate::Signature<Bls12_381>;
pub type AggregateSignature = crate::AggregateSignature<Bls12_381>;
