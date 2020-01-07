// Copyright (c) 2019-2020 Web 3 Foundation

//! Ring VRF zk SNARK verifier

use bellman::groth16::{verify_proof, prepare_verifying_key, PreparedVerifyingKey, VerifyingKey, Proof};
use zcash_primitives::jubjub::JubjubEngine;
use ff::Field;
use bellman::SynthesisError;
use crate::{AuthRoot, VRFInput, VRFOutput};

/// Verify a proof using the given CRS, VRF input and output, and
/// authentication root.
pub fn verify_unprepared<E: JubjubEngine>(
    verifying_key: &VerifyingKey<E>,
    zkproof: Proof<E>,
    vrf_input: VRFInput<E>,
    vrf_output: VRFOutput<E>,
    auth_root: AuthRoot<E>,
) -> Result<bool, SynthesisError> {
    let pvk = prepare_verifying_key::<E>(verifying_key);
    verify_prepared(&pvk, zkproof, vrf_input, vrf_output, auth_root)
}

// TODO: lifetime?
pub fn verify_prepared<E: JubjubEngine>(
    // Prepared means that 1 pairing e(alpha, beta) has been precomputed.
    // Makes sense, as we verify multiple proofs for the same circuit
    verifying_key: &PreparedVerifyingKey<E>,
    zkproof: Proof<E>,
    // Public inputs to check the proof against
    // in the order they should be assigned to the public inputs:
    // 1. VRF input, a point on Jubjub
    vrf_input: VRFInput<E>,
    // 2. VRF output, a point on Jubjub
    vrf_output: VRFOutput<E>,
    // 3. x-coordinate of the aggreagte public key
    auth_root: AuthRoot<E>,
) -> Result<bool, SynthesisError> {
    // TODO: subgroup checks
    // Public inputs are elements of the main curve (BLS12-381) scalar field (that matches Jubjub base field, that's the thing)
    let mut public_input = [E::Fr::zero(); 5];
    {
        let (x, y) = vrf_input.0.to_xy();
        public_input[0] = x;
        public_input[1] = y;
    }
    {
        let (x, y) = vrf_output.to_xy();
        public_input[2] = x;
        public_input[3] = y;
    }
    public_input[4] = auth_root.0;
    // Verify the proof
    verify_proof(verifying_key, &zkproof, &public_input[..])
}
