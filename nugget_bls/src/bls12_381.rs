
use ark_ff::fields::field_hashers::{DefaultFieldHasher};  // HashToField
use ark_ec::{
    AffineRepr, CurveGroup,
    pairing::{Pairing, prepare_g2, PairingOutput},
    hashing::{HashToCurve, HashToCurveError, curve_maps, map_to_curve_hasher::MapToCurveBasedHasher},
    bls12::Bls12Config,
};



pub use ark_bls12_381::{Bls12_381, G1Affine, G1Projective};

type H2C = MapToCurveBasedHasher::<
G1Projective,
    DefaultFieldHasher<sha2::Sha256>,
    curve_maps::wb::WBMap<ark_bls12_381::g1::Config>,
>;

pub fn hash_to_curve(domain: &[u8],message: &[u8]) -> Result<dleq_vrf::vrf::VrfInput<G1Affine>,HashToCurveError> {
    dleq_vrf::vrf::ark_hash_to_curve::<G1Affine,H2C>(domain,message)
}


