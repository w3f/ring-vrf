
// Copyright (c) 2019-2020 Web 3 Foundation
//
// Authors:
// - Jeffrey Burdges <jeff@web3.foundation>

use pairing::bls12_381::Bls12;
use pairing::Engine;
use zcash_primitives::jubjub::{JubjubBls12};

use crate::{JubjubEngineWithParams};
use neptune::poseidon::PoseidonConstants;
use typenum::U2;


lazy_static! {
    static ref JUBJUB_BLS12_381 : JubjubBls12 = {
        JubjubBls12::new()
    };

    // TODO: is there any difference?
    static ref POSEIDON_CONSTANTS_2: PoseidonConstants::<<Bls12 as Engine>::Fr, U2> = PoseidonConstants::new();
}

impl JubjubEngineWithParams for Bls12 {
    type Arity = U2;

    fn params() -> &'static JubjubBls12 {
        &JUBJUB_BLS12_381
    }

    fn poseidon_params() -> &'static PoseidonConstants<Self::Fr, Self::Arity> { &POSEIDON_CONSTANTS_2 }
}
