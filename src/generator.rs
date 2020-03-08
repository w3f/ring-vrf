// Copyright (c) 2019-2020 Web 3 Foundation
//
// Authors:
// - Wei Tang <hi@that.world>
// - Sergey Vasilyev <swasilyev@gmail.com>

//! ### Ring VRF zkSNARK SRS generator

use rand_core::{OsRng}; // RngCore

use bellman::groth16::{generate_random_parameters, Parameters,};
use bellman::SynthesisError;
use zcash_primitives::jubjub::JubjubEngine;

use crate::{Ring, Params};

/// Generates structured (meaning circuit-depending) Groth16
/// CRS (that comprises proving and verificaton keys) over BLS12-381
/// for the circuit defined in circuit.rs using OS RNG.
pub fn generate_crs<E: JubjubEngine>(params: &Params<E>) -> Result<Parameters<E>, SynthesisError> {
    let rng = &mut OsRng;
    let circuit = Ring {
        params,
        sk: None,
        vrf_input: None,
        auth_path: None,
    };
    generate_random_parameters(circuit, rng)
}
