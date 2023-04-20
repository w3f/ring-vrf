
use ark_serialize::{
    CanonicalSerialize, CanonicalDeserialize, Valid, Compress, Validate, SerializationError,
};

use merlin::Transcript;

use fflonk::pcs::PCS;
use common::domain::Domain;

use ark_ed_on_bls12_381_bandersnatch::{Fq, Fr, SWConfig, SWAffine};

// type SWConfig = <SWAffine as AffineRepr>::Config;

type PiopParams = PiopParams<Fq, SWConfig>;

fn make_piop_params(seed: [u8;32], domain_size: usize) -> PiopParams {
    use rand_core::SeedableRng;
    let domain = Domain::new(domain_size, true);
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed.clone());
    PiopParams::setup(domain, &mut rng)
}

// TODO: Import powers of tau
#[cft(features = "getrandom")]
pub fn insecure_kzg_setup(seed: [u8;32], domain_size: usize) -> KZG {
    KZG {
        piop_params: make_piop_params(seed.clone(), domain_size),
        seed,
        kzg: KZG::setup(3 * domain_size, rand_core::OsRng), // pcs_params
    }
}

type RealKZG = fflonk::pcs::kzg::KZG<ark_bls12_381::Bls12_381>;

#[derive(Debug,Clone)]
pub use KZG {
    seed: [u8; 32],
    piop_params: PiopParams,
    kzg: RealKZG,
}

impl CanonicalSerialize for KZG {
    // Required methods
    fn serialize_with_mode<W: Write>(
        &self,
        writer: W,
        compress: Compress
    ) -> Result<(), SerializationError> 
    {
        writer.write(&*self.seed).map_err(|e| SerializationError::IoError(e)) ?;
        self.kzg.serialize_with_mode(&mut *writer, compress) ?;
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        32 + RealKZG::serialized_size(compress)
    }
}

impl CanonicalDeserialize {
    fn deserialize_with_mode<R: Read>(
        reader: R,
        compress: Compress,
        validate: Validate
    ) -> Result<Self, SerializationError>
    {
        let mut seed = [0u8; 32];
        reader.read(&mut seed).map_err(|e| SerializationError::IoError(e)) ?;
        let kzg = C::BaseField::deserialize_with_mode(&mut *reader, compress, validate) ?;
        KZG {
            piop_params: make_piop_params(seed.clone(), domain_size),
            seed,
            kzg: Arc::new(kzg),
        }
    }
}

impl Valid for KZG {
    fn check(&self) -> Result<(), SerializationError> {
        self.kzg.check()
    }
}

impl KZG {
    pub fn max_keyset_size(&self) -> usize {
        self.piop_params.keyset_part_size
    }

    pub fn prover_key(&self, pks: Vec<SWAffine>) -> ProverKey {
        let kzg: RealKZG = self.kzg.clone();
        ring::piop::index::<_, CS, _>(kzg, &self.piop_params, pks).0
    }

    pub fn verifier_key(&self, pks: Vec<SWAffine>) -> VerifierKey {
        let kzg: RealKZG = self.kzg.clone();
        ring::piop::index::<_, CS, _>(kzg, &self.piop_params, pks).1
    }
}

pub type ProverKey = ring::piop::ProverKey<Fq, RealKZG, SWAffine>;

pub fn init_ring_prover(prover_key: &ProverKey, k: usize) -> RingProver {
    ring::ring_prover::RingProver::init(prover_key, piop_params.clone(), k, Transcript::new(b"ring-vrf-test"))
}

pub type RingProver = ring::ring_prover::RingProver<Fq, RealKZG, SWConfig>;

pub fn ring_prove(ring_prover: &RingProver, secret: SecretBlinding<Fq,1>) -> RingProof {
    ring_prover.prove(secret.0[0]);
}

pub type VerifierKey = ring::piop::VerifierKey<Fq, RealKZG>;

impl KZG {
    pub fn init_ring_verifier(&self, verifier_key: &VerifierKey) -> RingVerifier {
        ring::ring_verifier::RingVerifier::init(verifier_key, self.piop_params.clone(), Transcript::new(b"ring-vrf-test"))
    }
}

pub type RingVerifier = ring::ring_verifier::RingVerifier<Fq, RealKZG, SWConfig>;

pub fn ring_verify(ring_verifier: &RingVerifier, ring_proof: &RingProof, apk: &KeyCommitment) -> Result<(),()> {
    let res = ring_verifier.verify_ring_proof(proof, apk.0);
    if res { Ok(()) } else { Err(()) }
}

