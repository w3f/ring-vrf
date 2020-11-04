// Copyright (c) 2019-2020 Web 3 Foundation
//
// Authors:
// - Wei Tang <hi@that.world>
// - Sergey Vasilyev <swasilyev@gmail.com>
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### Ring VRF zk SNARK verifier

use bellman::groth16::{self, Proof}; // verify_proof, prepare_verifying_key, PreparedVerifyingKey, VerifyingKey

use crate::{
    SynthesisResult,
    SigningTranscript, RingRoot, VRFInOut
};
use bls12_381::Bls12;
use jubjub::ExtendedPoint;
use group::Curve;


impl RingRoot {
    /// Verify a proof using the given authentication root, VRF input and output,
    /// verifying key aka CRS, and paramaters.
    ///
    /// In this, we support an unprepared verifying key that possesses
    /// serialization methods:
    /// https://docs.rs/bellman/0.6.0/bellman/groth16/struct.VerifyingKey.html
    pub fn ring_vrf_verify_unprepared<T>(
        &self, // auth_root
        vrf_inout: VRFInOut,
        extra: T,
        zkproof: Proof<Bls12>,
        verifying_key: &groth16::VerifyingKey<Bls12>,
    ) -> SynthesisResult<bool> 
    where T: SigningTranscript, 
    {
        let pvk = groth16::prepare_verifying_key::<Bls12>(verifying_key);
        self.ring_vrf_verify(vrf_inout, extra, zkproof, &pvk)
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
        vrf_inout: VRFInOut,
        // 3. extra message signed along with the VRF
        mut extra: T,
        // 
        zkproof: Proof<Bls12>,
        // Prepared means that 1 pairing e(alpha, beta) has been precomputed.
        // Makes sense, as we verify multiple proofs for the same circuit
        verifying_key: &groth16::PreparedVerifyingKey<Bls12>,
    ) -> SynthesisResult<bool> 
    where T: SigningTranscript, 
    {
        // TODO: lifetime?
        // TODO: Check params.auth_depth perhaps?
        // TODO: subgroup checks
        // Public inputs are elements of the main curve (BLS12-381) scalar field (that matches Jubjub base field, that's the thing)
        let input = ExtendedPoint::from(vrf_inout.input.as_point().clone()).to_affine();
        let output = vrf_inout.output.as_point().to_affine();
        let (x1, y1) = (input.get_u(), input.get_v());
        let (x2, y2) = (output.get_u(), output.get_v());
        // We employ the challenge_scalar method since it hashes into a field,
        // but we're hashing into the jubjub base field not the scalar field
        // here, so maybe the method should be renamed.
        let extra = extra.challenge_scalar(b"extra-msg");
        let public_input: [bls12_381::Scalar; 6] = [ x1, y1, x2, y2, extra, self.0.clone() ];
        // Verify the proof
        Ok(groth16::verify_proof(verifying_key, &zkproof, &public_input[..]).is_ok())
    }
}

