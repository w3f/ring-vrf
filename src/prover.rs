use bellman::groth16::{create_random_proof, Parameters, Proof,};
use pairing::bls12_381::{Bls12, Fr};
use zcash_primitives::jubjub::{JubjubBls12, edwards, Unknown, fs, PrimeOrder};
use super::circuit::Ring;
use rand_core::OsRng;

pub fn prove(
    params: &JubjubBls12,
    proving_key: &Parameters<Bls12>,
    sk: fs::Fs,
    vrf_base: edwards::Point<Bls12, PrimeOrder>,
    auth_path: Vec<Option<(Fr, bool)>>
) -> Result<Proof<Bls12>, ()> {
//    let params = &JubjubBls12::new();
    let mut rng = OsRng;
    let instance = Ring {
        params,
        sk: Some(sk),
        vrf_input: Some(vrf_base),
        auth_path: auth_path,
    };
    let proof =
        create_random_proof(instance, proving_key, &mut rng).expect("proving should not fail");
    Ok(proof)
}
