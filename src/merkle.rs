use ff::{PrimeField, BitIterator};
use pairing::bls12_381::Fr;
use zcash_primitives::jubjub::JubjubEngine;
use zcash_primitives::pedersen_hash;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PathDirection {
    Left,
    Right,
}

impl PathDirection {
    pub fn random<R: rand_core::RngCore>(rng: &mut R) -> Self {
        if rng.next_u32() % 2 == 0 {
            PathDirection::Left
        } else {
            PathDirection::Right
        }
    }
}

pub fn aggregated_pkx<E: JubjubEngine>(
    params: &E::Params,
    pk_x: E::Fr,
    path: &[(E::Fr, PathDirection)]
) -> E::Fr {
    let mut cur = pk_x.clone();

    for (i, (uncle, direction)) in path.iter().enumerate() {
        let (lhs, rhs) = match direction {
            PathDirection::Left => (&cur, uncle),
            PathDirection::Right => (uncle, &cur),
        };

        let mut lhs = BitIterator::new(lhs.into_repr()).collect::<Vec<bool>>();
        let mut rhs = BitIterator::new(rhs.into_repr()).collect::<Vec<bool>>();

        lhs.reverse();
        rhs.reverse();

        cur = pedersen_hash::pedersen_hash::<E, _>(
            pedersen_hash::Personalization::MerkleTree(i),
            lhs.into_iter()
                .take(Fr::NUM_BITS as usize)
                .chain(rhs.into_iter().take(Fr::NUM_BITS as usize)),
            params,
        ).to_xy().0;
    }

    cur
}
