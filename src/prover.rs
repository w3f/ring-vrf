use bellman::groth16::{create_random_proof, Parameters, Proof};
use zcash_primitives::jubjub::{JubjubEngine, edwards, PrimeOrder};
use rand_core::OsRng;
use crate::{Ring, Params, AuthPath};

pub fn prove<E: JubjubEngine>(
    proving_key: &Parameters<E>,
    sk: E::Fs,
    vrf_base: edwards::Point<E, PrimeOrder>,
    auth_path: AuthPath<E>,
    params: &Params<E>,
) -> Result<Proof<E>, ()> {
    let mut rng = OsRng;
    let instance = Ring {
        params,
        sk: Some(sk),
        vrf_input: Some(vrf_base),
        auth_path: Some(auth_path),
    };
    let proof =
        create_random_proof(instance, proving_key, &mut rng).expect("proving should not fail");
    Ok(proof)
}
