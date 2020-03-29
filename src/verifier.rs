// Copyright (c) 2019-2020 Web 3 Foundation
//
// Authors:
// - Wei Tang <hi@that.world>
// - Sergey Vasilyev <swasilyev@gmail.com>
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### Ring VRF zk SNARK verifier

use bellman::groth16::{verify_proof, prepare_verifying_key, PreparedVerifyingKey, VerifyingKey, Proof};
use zcash_primitives::jubjub::JubjubEngine;
use ff::Field;
use bellman::SynthesisError;
use crate::{Params, AuthRoot, VRFInOut};

/// Verify a proof using the given CRS, VRF input and output, and
/// authentication root.
pub fn verify_unprepared<E: JubjubEngine>(
    verifying_key: &VerifyingKey<E>,
    zkproof: Proof<E>,
    vrf_inout: VRFInOut<E>,
    auth_root: AuthRoot<E>,
    params: &Params<E>,
) -> Result<bool, SynthesisError> {
    let pvk = prepare_verifying_key::<E>(verifying_key);
    verify_prepared(&pvk, zkproof, vrf_inout, auth_root, params)
}

// TODO: lifetime?
pub fn verify_prepared<E: JubjubEngine>(
    // Prepared means that 1 pairing e(alpha, beta) has been precomputed.
    // Makes sense, as we verify multiple proofs for the same circuit
    verifying_key: &PreparedVerifyingKey<E>,
    //
    zkproof: Proof<E>,
    // Public inputs to check the proof against
    // in the order they should be assigned to the public inputs:
    // 1. VRF input and output points on Jubjub prepared togther
    vrf_inout: VRFInOut<E>,
    // 2. Signer set specified by a Merkle root, given as x-coordinate rom a Pederson hash
    auth_root: AuthRoot<E>,
    params: &Params<E>,
) -> Result<bool, SynthesisError> {
    // TODO: Check params.auth_depth perhaps?
    // TODO: subgroup checks
    // Public inputs are elements of the main curve (BLS12-381) scalar field (that matches Jubjub base field, that's the thing)
    let mut public_input = [E::Fr::zero(); 5];
    {
        let (x, y) = vrf_inout.input.0.mul_by_cofactor(&params.engine).to_xy();
        public_input[0] = x;
        public_input[1] = y;
    }
    {
        let (x, y) = vrf_inout.output.0.mul_by_cofactor(&params.engine).to_xy();
        public_input[2] = x;
        public_input[3] = y;
    }
    public_input[4] = auth_root.0;
    // Verify the proof
    verify_proof(verifying_key, &zkproof, &public_input[..])
}
