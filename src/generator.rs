use rand_core::{OsRng}; // RngCore

use bellman::groth16::{generate_random_parameters, Parameters,};
use bellman::SynthesisError;
use pairing::bls12_381::Bls12;
use zcash_primitives::jubjub::JubjubBls12;

use crate::{Ring, PathDirection};

/// Generates structured (meaning circuit-depending) Groth16
/// CRS (that comprises proving and verificaton keys) over BLS12-381
/// for the circuit defined in circuit.rs using OS RNG.
pub fn generate_crs() -> Result<Parameters<Bls12>, SynthesisError> {
    let params = &JubjubBls12::new();
    let rng = &mut OsRng;
    let circuit = Ring {
        params,
        sk: None,
        vrf_input: None,
        auth_path: vec![None; 10],
    };
    generate_random_parameters(circuit, rng)
}
