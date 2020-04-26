
// Copyright (c) 2019-2020 Web 3 Foundation
//
// Authors:
// - Jeffrey Burdges <jeff@web3.foundation>

use pairing::bls12_381::Bls12;
use zcash_primitives::jubjub::{JubjubBls12};

use crate::{JubjubEngineWithParams};


lazy_static! {
    static ref JUBJUB_BLS12_381 : JubjubBls12 = {
        JubjubBls12::new()
    }; 
}

impl JubjubEngineWithParams for Bls12 {
    fn params() -> &'static JubjubBls12 { // <Self as JubjubEngine>::Params
        &JUBJUB_BLS12_381
    }
}
