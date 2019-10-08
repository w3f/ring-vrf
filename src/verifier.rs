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
    // 1. public key, a point on Jubjub // TODO: Merkle root
    pk: edwards::Point<E, PrimeOrder>,
    // 2. VRF seed for the epoch, a point on Jubjub //TODO: name
    vrf_base: edwards::Point<E, PrimeOrder>,
    // 3. VRF output, a point on Jubjub
    vrf_output: edwards::Point<E, PrimeOrder>,
    root: E::Fr,
) -> Result<bool, SynthesisError> {
    // TODO: subgroup checks

    // Public inputs are elements of the main curve (BLS12-381) scalar field.
    let mut public_input = [E::Fr::zero(); 7];
    {
        let (x, y) = pk.to_xy();
        public_input[0] = x;
        public_input[1] = y;
    }
    {
        let (x, y) = vrf_base.to_xy();
        public_input[2] = x;
        public_input[3] = y;
    }
    {
        let (x, y) = vrf_output.to_xy();
        public_input[4] = x;
        public_input[5] = y;
    }
    public_input[6] = root;
    // Verify the proof
    verify_proof(verifying_key, &zkproof, &public_input[..])
}