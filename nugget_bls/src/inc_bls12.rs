
use ark_ff::fields::field_hashers::{DefaultFieldHasher};  // HashToField
use ark_ec::{
    // AffineRepr, CurveGroup,
    hashing::{HashToCurveError, curve_maps, map_to_curve_hasher::MapToCurveBasedHasher}, // HashToCurve
    // bls12::Bls12Config,
};

use dleq_vrf::{vrf::{VrfInput, IntoVrfInput},transcript::{AsLabel,IsLabel}};

pub use curve::{G1Affine, G1Projective};

type H2C = MapToCurveBasedHasher::<
    G1Projective,
    DefaultFieldHasher<sha2::Sha256>,
    curve_maps::wb::WBMap<curve::g1::Config>,
>;

pub fn hash_to_curve(domain: impl AsLabel,message: &[u8]) -> Result<dleq_vrf::vrf::VrfInput<G1Affine>,HashToCurveError> {
    dleq_vrf::vrf::ark_hash_to_curve::<G1Affine,H2C>(domain,message)
}

/// We'd ideally define `Message` once for both curves.  Annoyingly, 
/// we've some rustc bug here in that rustc cannot distinguish between
/// the traits `IntoVrfInput<curve::G1Affine>` for different curves.
pub struct Message<'a> {
    pub domain: &'a [u8],
    pub message: &'a [u8],
}

// pub type Message<'a> = crate::Message<'a>;
impl<'a> IntoVrfInput<G1Affine> for Message<'a> {
    fn into_vrf_input(self) -> VrfInput<G1Affine> {
        hash_to_curve(IsLabel(self.domain),self.message)
        .expect("Hash-to-curve error, IRTF spec forbids messages longer than 2^16!")
    }
}

pub type SecretKey = crate::SecretKey<P>;
pub type PublicKeyG1 = crate::PublicKeyG1<P>;
pub type Signature = crate::Signature<P>;
pub type AggregationKey = crate::AggregationKey<P>;
pub type AggregateSignature = crate::AggregateSignature<P>;
