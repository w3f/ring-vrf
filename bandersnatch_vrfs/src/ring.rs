extern crate alloc;

use alloc::vec::Vec;

use ark_ff::{Field, MontFp};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid,
    Validate, Write,
};
use ark_std::{rand::{Rng, SeedableRng}, vec};
use fflonk::pcs::PCS;
use merlin::Transcript;
use ring::Domain;
use ring::ring::Ring;

use crate::bandersnatch::{Fq, SWAffine, SWConfig, BandersnatchConfig};
use crate::bls12_381::Bls12_381;
use crate::bls12_381;

type RealKZG = fflonk::pcs::kzg::KZG<Bls12_381>;

type PcsParams = fflonk::pcs::kzg::urs::URS<Bls12_381>;

pub type PiopParams = ring::PiopParams<Fq, SWConfig>;
pub type RingProof = ring::RingProof<Fq, RealKZG>;
pub type RingProver = ring::ring_prover::RingProver<Fq, RealKZG, SWConfig>;
pub type RingVerifier = ring::ring_verifier::RingVerifier<Fq, RealKZG, SWConfig>;

pub type ProverKey = ring::ProverKey<Fq, RealKZG, SWAffine>;
pub type VerifierKey = ring::VerifierKey<Fq, RealKZG>;

pub type KzgVk = fflonk::pcs::kzg::params::RawKzgVerifierKey<Bls12_381>;

pub type RingCommitment = Ring<bls12_381::Fr, Bls12_381, BandersnatchConfig>;

// A point on Jubjub, not belonging to the prime order subgroup.
// Used as the point to start summation from, as inf doesn't have an affine representation.
const COMPLEMENT_POINT: crate::Jubjub = {
    const X: Fq = Fq::ZERO;
    const Y: Fq = MontFp!("11982629110561008531870698410380659621661946968466267969586599013782997959645");
    crate::Jubjub::new_unchecked(X, Y)
};

// Just a point of an unknown dlog.
pub(crate) const PADDING_POINT: crate::Jubjub = {
    const X: Fq = MontFp!("25448400713078632486748382313960039031302935774474538965225823993599751298535");
    const Y: Fq = MontFp!("24382892199244280513693545286348030912870264650402775682704689602954457435722");
    crate::Jubjub::new_unchecked(X, Y)
};

pub fn make_piop_params(domain_size: usize) -> PiopParams {
    let domain = Domain::new(domain_size, true);
    PiopParams::setup(domain, crate::BLINDING_BASE, COMPLEMENT_POINT)
}

pub fn make_ring_verifier(verifier_key: VerifierKey, domain_size: usize) -> RingVerifier {
    let piop_params = make_piop_params(domain_size);
    RingVerifier::init(verifier_key, piop_params, Transcript::new(b"ring-vrf-test"))
}

#[derive(Clone)]
pub struct KZG {
    pub domain_size: u32,
    piop_params: PiopParams,
    pub pcs_params: PcsParams,
}

#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct StaticVerifierKey {
    // `N` Lagrangian bases `L1(tau).G1, ..., LN(tau).G1`, where `N=2^m` is domain size.
    // Used to create/update the commitment to the public keys.
    pub lag_g1: Vec<bls12_381::G1Affine>,
    // KZG vk with unprepared G2 points.
    pub kzg_vk: KzgVk,
}

#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct StaticProverKey {
    // `3N+1` monomial bases `G1, tau.G1, ..., tau^(3N).G1`, where `N=2^m` is domain size.
    pub mon_g1: Vec<bls12_381::G1Affine>,
    // KZG vk with unprepared G2 points. Used in the Fiat-Shamir transform.
    pub kzg_vk: KzgVk,
}

impl KZG {
    // TODO: Import powers of tau
    pub fn insecure_kzg_setup<R: Rng>(domain_size: u32, rng: &mut R) -> Self {
        let piop_params = make_piop_params(domain_size as usize);
        let pcs_params = RealKZG::setup(3 * (domain_size as usize), rng);
        KZG {
            domain_size,
            piop_params,
            pcs_params,
        }
    }

    pub fn kzg_setup(domain_size: usize, srs: StaticProverKey) -> Self {
        let piop_params = make_piop_params(domain_size);
        let pcs_params = fflonk::pcs::kzg::urs::URS  {
            powers_in_g1: srs.mon_g1,
            powers_in_g2: vec![srs.kzg_vk.g2, srs.kzg_vk.tau_in_g2],
        };
        KZG {
            domain_size: domain_size as u32,
            piop_params,
            pcs_params,
        }
    }

    // Testing only kzg setup.
    pub fn testing_kzg_setup(preseed: [u8;32], domain_size: u32) -> Self {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(preseed);
        Self::insecure_kzg_setup(domain_size, &mut rng)
    }

    pub fn max_keyset_size(&self) -> usize {
        self.piop_params.keyset_part_size
    }

    /*
    // Unecessary but right now our own padding is broken, and it's maybe not flexible enough anyways.
	// https://github.com/w3f/ring-proof/blob/master/ring/src/piop/params.rs#L56
    pub fn padding_point(&self) -> SWAffine {
        let mut seed = self.seed.clone();
        seed.reverse();
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
        SWAffine::rand(&mut rng)
    }
    */

    pub fn prover_key(&self, pks: Vec<SWAffine>) -> ProverKey {
        ring::index(self.pcs_params.clone(), &self.piop_params, pks).0
    }

    pub fn verifier_key(&self, pks: Vec<SWAffine>) -> VerifierKey {
        ring::index(self.pcs_params.clone(), &self.piop_params, pks).1
    }

    /// `k` is the prover secret index in [0..keyset_size).
    pub fn init_ring_prover(&self, prover_key: ProverKey, k: usize) -> RingProver {
        RingProver::init(prover_key, self.piop_params.clone(), k, Transcript::new(b"ring-vrf-test"))
    }

    pub fn init_ring_verifier(&self, verifier_key: VerifierKey) -> RingVerifier {
        RingVerifier::init(verifier_key, self.piop_params.clone(), Transcript::new(b"ring-vrf-test"))
    }
}

impl CanonicalSerialize for KZG {
    // Required methods
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress
    ) -> Result<(), SerializationError> 
    {
        self.domain_size.serialize_compressed(&mut writer) ?;
        self.pcs_params.serialize_with_mode(&mut writer, compress) ?;
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.domain_size.compressed_size()
        + self.pcs_params.serialized_size(compress)
    }
}

impl CanonicalDeserialize for KZG {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate
    ) -> Result<Self, SerializationError>
    {
        let domain_size = <u32 as CanonicalDeserialize>::deserialize_compressed(&mut reader) ?;
        let piop_params = make_piop_params(domain_size as usize);
        let pcs_params = <PcsParams as CanonicalDeserialize>::deserialize_with_mode(&mut reader, compress, validate) ?;
        Ok(KZG {
            domain_size,
            piop_params,
            pcs_params,
        })
    }
}

impl Valid for KZG {
    fn check(&self) -> Result<(), SerializationError> {
        self.pcs_params.check()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_complement_point() {
        assert_eq!(COMPLEMENT_POINT, ring::find_complement_point::<crate::bandersnatch::BandersnatchConfig>());
    }

    #[test]
    fn check_padding_point() {
        let padding_point = ring::hash_to_curve::<crate::Jubjub>(b"w3f/ring-proof/common/padding");
        assert_eq!(PADDING_POINT, padding_point);
    }
}
