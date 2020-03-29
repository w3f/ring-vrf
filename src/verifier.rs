// Copyright (c) 2019-2020 Web 3 Foundation
//
// Authors:
// - Wei Tang <hi@that.world>
// - Sergey Vasilyev <swasilyev@gmail.com>
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### Ring VRF zk SNARK verifier

use bellman::groth16::{self, Proof}; // verify_proof, prepare_verifying_key, PreparedVerifyingKey, VerifyingKey
use zcash_primitives::jubjub::JubjubEngine;
use ff::Field;
use bellman::SynthesisError;

use crate::{Params, AuthRoot, VRFInOut};
use crate::SigningTranscript;


impl<E: JubjubEngine> AuthRoot<E> {
    /// Verify a proof using the given authentication root, VRF input and output,
    /// verifying key aka CRS, and paramaters.
    ///
    /// In this, we support an unprepared verifying key that possesses
    /// serialization methods:
    /// https://docs.rs/bellman/0.6.0/bellman/groth16/struct.VerifyingKey.html
    pub fn ring_vrf_verify_unprepared<T>(
        &self, // auth_root
        vrf_inout: VRFInOut<E>,
        extra: T,
        zkproof: Proof<E>,
        verifying_key: &groth16::VerifyingKey<E>,
        params: &Params<E>,
    ) -> Result<bool, SynthesisError> 
    where T: SigningTranscript, 
    {
        let pvk = groth16::prepare_verifying_key::<E>(verifying_key);
        self.ring_vrf_verify(vrf_inout, extra, zkproof, &pvk, params)
    }

    /// Verify a proof using the given authentication root, VRF input and output,
    /// prepared verifying key aka CRS, and paramaters.
    /// 
    /// In this, we support an prepared verifying key in which one pairing
    /// e(alpha, beta) has been precomputed to improve performance when
    /// reusing the same circuit:
    /// https://docs.rs/bellman/0.6.0/bellman/groth16/struct.PreparedVerifyingKey.html
    pub fn ring_vrf_verify<T>(
        // Public inputs to check the proof against
        // in the order they should be assigned to the public inputs:
        // 1. Signer set specified by a Merkle root, given as x-coordinate rom a Pederson hash
        &self, // auth_root
        // 2. VRF input and output points on Jubjub prepared togther
        vrf_inout: VRFInOut<E>,
        // 3. extra message signed along with the VRF
        mut extra: T,
        // 
        zkproof: Proof<E>,
        // Prepared means that 1 pairing e(alpha, beta) has been precomputed.
        // Makes sense, as we verify multiple proofs for the same circuit
        verifying_key: &groth16::PreparedVerifyingKey<E>,
        params: &Params<E>,
    ) -> Result<bool, SynthesisError> 
    where T: SigningTranscript, 
    {
        // TODO: lifetime?
        // TODO: Check params.auth_depth perhaps?
        // TODO: subgroup checks
        // Public inputs are elements of the main curve (BLS12-381) scalar field (that matches Jubjub base field, that's the thing)
        let mut public_input = [E::Fr::zero(); 6];
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
        // We employ the challenge_scalar method since it hashes into a field,
        // but we're hashing into the jubjub base field not the scalar field
        // here, so maybe the method should be renamed.
        public_input[4] = extra.challenge_scalar(b"extra-msg");
        public_input[5] = self.0.clone();
        // Verify the proof
        groth16::verify_proof(verifying_key, &zkproof, &public_input[..])
    }
}

