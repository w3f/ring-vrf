// Copyright (c) 2019-2020 Web 3 Foundation
//
// Authors:
// - Sergey Vasilyev <swasilyev@gmail.com>

//! ### Ring VRF zk SNARK prover

use bellman::groth16::{create_random_proof, Parameters, Proof};
use zcash_primitives::jubjub::JubjubEngine;
use rand_core::OsRng;
use crate::{Ring, Params, AuthPath, VRFInput, SecretKey};

pub fn prove<E: JubjubEngine>(
    proving_key: &Parameters<E>,
    sk: SecretKey<E>,
    vrf_input: VRFInput<E>,
    auth_path: AuthPath<E>,
    params: &Params<E>,
) -> Result<Proof<E>, ()> {
    let mut rng = OsRng;
    let instance = Ring {
        params,
        sk: Some(sk),
        vrf_input: Some(vrf_input),
        auth_path: Some(auth_path),
    };
    let proof =
        create_random_proof(instance, proving_key, &mut rng).expect("proving should not fail");
    Ok(proof)
}
