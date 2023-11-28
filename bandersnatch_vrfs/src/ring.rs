extern crate alloc;
use alloc::vec::Vec;

use ark_std::rand::{Rng, SeedableRng};

use ark_serialize::{
    CanonicalSerialize, CanonicalDeserialize, Valid, Compress, Validate, SerializationError,
    Write, Read,
};

use merlin::Transcript;

use fflonk::pcs::PCS;
use ring::Domain;

use crate::bandersnatch::{Fq, SWConfig, SWAffine};  // Fr
use crate::bls12_381;

type RealKZG = fflonk::pcs::kzg::KZG<bls12_381::Bls12_381>;

type PcsParams = fflonk::pcs::kzg::urs::URS<bls12_381::Bls12_381>;

pub type PiopParams = ring::PiopParams<Fq, SWConfig>;
pub type RingProof = ring::RingProof<Fq, RealKZG>;
pub type RingProver = ring::ring_prover::RingProver<Fq, RealKZG, SWConfig>;
pub type RingVerifier = ring::ring_verifier::RingVerifier<Fq, RealKZG, SWConfig>;

pub type ProverKey = ring::ProverKey<Fq, RealKZG, SWAffine>;
pub type VerifierKey = ring::VerifierKey<Fq, RealKZG>;

pub fn make_piop_params(domain_size: usize) -> PiopParams {
    let domain = Domain::new(domain_size, true);
    let seed = ring::find_complement_point::<crate::bandersnatch::BandersnatchConfig>();
    PiopParams::setup(domain, crate::BLINDING_BASE, seed)
}

pub fn make_ring_verifier(verifier_key: VerifierKey, domain_size: usize) -> RingVerifier {
    let piop_params = make_piop_params(domain_size);
    RingVerifier::init(verifier_key, piop_params, Transcript::new(b"ring-vrf-test"))
}

#[derive(Clone)]
pub struct KZG {
    pub domain_size: u32,
    piop_params: PiopParams,
    pcs_params: PcsParams,
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

