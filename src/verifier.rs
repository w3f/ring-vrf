use bellman::groth16::{verify_proof, PreparedVerifyingKey, Proof,};
use pairing::bls12_381::Bls12;
use zcash_primitives::jubjub::{edwards, PrimeOrder, JubjubBls12, Unknown, JubjubEngine};
use ff::Field;

use bellman::SynthesisError;

// TODO: lifetime?
pub fn verify<E: JubjubEngine>(
    params: &E::Params,
    // Prepared means that 1 pairing e(alpha, beta) has been precomputed.
    // Makes sense, as we verify multiple proofs for the same circuit
    verifying_key: &PreparedVerifyingKey<E>,
    zkproof: Proof<E>,
    // Public inputs to check the proof against
    // in the order they should be assigned to the public inputs:
    // 1. VRF input, a point on Jubjub
    vrf_input: edwards::Point<E, PrimeOrder>,
    // 2. VRF output, a point on Jubjub
    vrf_output: edwards::Point<E, PrimeOrder>,
    // 3. x-coordinate of the aggreagte public key
    apk_x: E::Fr,
) -> Result<bool, SynthesisError> {
    // TODO: subgroup checks
    // Public inputs are elements of the main curve (BLS12-381) scalar field (that matches Jubjub base field, that's the thing)
    let mut public_input = [E::Fr::zero(); 5];
    {
        let (x, y) = vrf_input.to_xy();
        public_input[0] = x;
        public_input[1] = y;
    }
    {
        let (x, y) = vrf_output.to_xy();
        public_input[2] = x;
        public_input[3] = y;
    }
    public_input[4] = apk_x;
    // Verify the proof
    verify_proof(verifying_key, &zkproof, &public_input[..])
}