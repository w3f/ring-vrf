// Copyright (c) 2019-2020 Web 3 Foundation
//
// Authors:
// - Wei Tang <hi@that.world>
// - Sergey Vasilyev <swasilyev@gmail.com>

//! ### Ring VRF zkSNARK SRS generator


use bellman::groth16;

use crate::{rand_hack, SynthesisResult};
use bls12_381::Bls12;


/// Generates structured (meaning circuit-depending) Groth16
/// CRS (that comprises proving and verificaton keys) over BLS12-381
/// for the circuit defined in circuit.rs using OS RNG.
pub fn generate_crs(depth: u32) -> SynthesisResult<groth16::Parameters<Bls12>>
{
    let circuit = crate::circuit::RingVRF {
        depth,
        sk: None,
        vrf_input: None,
        extra: None,
        copath: None,
    };
    groth16::generate_random_parameters(circuit, &mut rand_hack())
}
