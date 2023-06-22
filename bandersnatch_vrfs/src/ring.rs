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

use ark_ed_on_bls12_381_bandersnatch::{Fq, Fr, SWConfig, SWAffine};

type RealKZG = fflonk::pcs::kzg::KZG<ark_bls12_381::Bls12_381>;

type PcsParams = fflonk::pcs::kzg::urs::URS<ark_bls12_381::Bls12_381>;

pub type PiopParams = ring::PiopParams<Fq, SWConfig>;
pub type RingProof = ring::RingProof<Fq, RealKZG>;
pub type RingProver = ring::ring_prover::RingProver<Fq, RealKZG, SWConfig>;
pub type RingVerifier = ring::ring_verifier::RingVerifier<Fq, RealKZG, SWConfig>;

pub type ProverKey = ring::ProverKey<Fq, RealKZG, SWAffine>;
pub type VerifierKey = ring::VerifierKey<Fq, RealKZG>;

fn make_piop_params(seed: [u8; 32], domain_size: usize) -> PiopParams {
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed.clone());
    let domain = Domain::new(domain_size, true);
    PiopParams::setup(domain, &mut rng)
}

#[derive(Clone)]
pub struct KZG {
    seed: [u8; 32],
    piop_params: PiopParams,
    pcs_params: PcsParams,
}

impl KZG {
    // TODO: Import powers of tau
    pub fn insecure_kzg_setup<R: Rng>(seed: [u8;32], domain_size: usize, rng: &mut R) -> Self {
        let piop_params = make_piop_params(seed, domain_size);

        let pcs_params = RealKZG::setup(3 * domain_size, rng);
        KZG {
            seed,
            piop_params,
            pcs_params,
        }
    }

    // Testing only kzg setup.
    pub fn testing_kzg_setup(seed: [u8;32], domain_size: usize) -> Self {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
        Self::insecure_kzg_setup(seed, domain_size, &mut rng)
    }

    pub fn max_keyset_size(&self) -> usize {
        self.piop_params.keyset_part_size
    }

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
        writer.write(&self.seed).map_err(|e| SerializationError::IoError(e))?;
        self.pcs_params.serialize_with_mode(&mut writer, compress)
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        32 + self.pcs_params.serialized_size(compress)
    }
}

impl CanonicalDeserialize for KZG {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate
    ) -> Result<Self, SerializationError>
    {
        let mut seed = [0u8; 32];
        reader.read(&mut seed).map_err(|e| SerializationError::IoError(e))?;
        let pcs_params = PcsParams::deserialize_with_mode(&mut reader, compress, validate)?;
        // TODO: @jeff should we serialize the original `domain_size` to get it back here?
        // Or shoud we use a global constant value?
        let domain_size = 2usize.pow(10); // FIXME
        let piop_params = make_piop_params(seed, domain_size);
        Ok(KZG {
            seed,
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

