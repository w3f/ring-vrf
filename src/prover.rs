// Copyright (c) 2019-2020 Web 3 Foundation
//
// Authors:
// - Sergey Vasilyev <swasilyev@gmail.com>
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### Ring VRF zk SNARK prover

use bellman::{
    SynthesisError,
    groth16::{self, Proof}, // create_random_proof, ParameterSource, Parameters
};
use zcash_primitives::jubjub::JubjubEngine;
use rand_core::{RngCore,CryptoRng,OsRng};
use crate::{RingVRF, Params, AuthPath, VRFInput, SecretKey};

impl<E: JubjubEngine> SecretKey<E> {
    /// Create ring VRF signature using specified randomness source.
    pub fn ring_vrf_sign_with_rng<R,P>(
        &self,
        vrf_input: VRFInput<E>,
        auth_path: AuthPath<E>,
        proving_key: P,
        params: &Params<E>,
        rng: &mut R,
    ) -> Result<Proof<E>, SynthesisError> 
    where P: groth16::ParameterSource<E>, R: RngCore+CryptoRng
    {
        let instance = RingVRF {
            params,
            sk: Some(self.clone()),
            vrf_input: Some(vrf_input.0.mul_by_cofactor(&params.engine)),
            auth_path: Some(auth_path),
        };
        groth16::create_random_proof(instance, proving_key, rng)
    } 

    /// Create ring VRF signature using system randomness.
    pub fn ring_vrf_sign(
        &self,
        vrf_input: VRFInput<E>,
        auth_path: AuthPath<E>,
        proving_key: &groth16::Parameters<E>,
        params: &Params<E>,
    ) -> Result<Proof<E>, SynthesisError> 
    {
        self.ring_vrf_sign_with_rng(vrf_input, auth_path, proving_key, params, &mut OsRng)
    } 
}

