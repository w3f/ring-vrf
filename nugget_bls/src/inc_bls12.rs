
use ark_ff::fields::field_hashers::{DefaultFieldHasher};  // HashToField
use ark_ec::{
    // AffineRepr, CurveGroup,
    hashing::{HashToCurveError, curve_maps, map_to_curve_hasher::MapToCurveBasedHasher}, // HashToCurve
    // bls12::Bls12Config,
};

use dleq_vrf::vrf::{VrfInput, IntoVrfInput};

use curve::{G1Affine, G1Projective};


type H2C = MapToCurveBasedHasher::<
G1Projective,
    DefaultFieldHasher<sha2::Sha256>,
    curve_maps::wb::WBMap<curve::g1::Config>,
>;

pub fn hash_to_curve(domain: &[u8],message: &[u8]) -> Result<dleq_vrf::vrf::VrfInput<G1Affine>,HashToCurveError> {
    dleq_vrf::vrf::ark_hash_to_curve::<G1Affine,H2C>(domain,message)
}

pub type Message<'a> = crate::Message<'a>;
impl<'a> IntoVrfInput<G1Affine> for Message<'a> {
    fn into_vrf_input(self) -> VrfInput<G1Affine> {
        hash_to_curve(self.domain,self.message)
        .expect("Hash-to-curve error, IRTF spec forbids messages longer than 2^16!")
    }
}

pub type SecretKey = crate::SecretKey<P>;
pub type PublicKey = crate::PublicKey<P>;
pub type Signature = crate::Signature<P>;
pub type AggregateSignature = crate::AggregateSignature<P>;
