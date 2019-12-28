use bellman::groth16::{create_random_proof, Parameters, Proof};
use pairing::bls12_381::{Bls12, Fr};
use zcash_primitives::jubjub::{JubjubBls12, edwards, fs, PrimeOrder};
use rand_core::OsRng;
use crate::{Ring, PathDirection};

pub fn prove(
    params: &JubjubBls12,
    proving_key: &Parameters<Bls12>,
    sk: fs::Fs,
    vrf_base: edwards::Point<Bls12, PrimeOrder>,
    auth_path: Vec<(Fr, PathDirection)>
) -> Result<Proof<Bls12>, ()> {
    let mut rng = OsRng;
    let instance = Ring {
        params,
        sk: Some(sk),
        vrf_input: Some(vrf_base),
        auth_path: auth_path.into_iter().map(|a| Some(a)).collect(),
    };
    let proof =
        create_random_proof(instance, proving_key, &mut rng).expect("proving should not fail");
    Ok(proof)
}
