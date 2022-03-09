// https://github.com/filecoin-project/rust-fil-proofs/blob/8e7c5a04c9b3e94a07809736cda3bdf618ac6921/storage-proofs/core/src/gadgets/por.rs#L5

use ff::PrimeField;
use bellman::{ConstraintSystem, SynthesisError};
use bellman::gadgets::num;
use bellman::gadgets::boolean::{Boolean, AllocatedBit};
use crate::insertion::insert;
use crate::{RingSecretCopath, PoseidonArity};
use neptune::circuit::poseidon_hash;

impl<A: 'static + PoseidonArity> RingSecretCopath<A> {
    pub fn synthesize<CS: ConstraintSystem<bls12_381::Scalar>>(
        self,
        mut cs: CS,
        mut cur: num::AllocatedNum<bls12_381::Scalar>,
    ) -> Result<(num::AllocatedNum<bls12_381::Scalar>, Vec<Boolean>), SynthesisError> {
        let arity = A::to_usize();

        if arity == 0 {
            // Nothing to do here.
            assert!(self.0.is_empty());
            return Ok((cur, vec![]));
        }

        assert_eq!(1, arity.count_ones(), "arity must be a power of two");
        let index_bit_count = arity.trailing_zeros() as usize;

        let mut auth_path_bits = Vec::with_capacity(self.0.len());

        for (i, path_element) in self.0.into_iter().enumerate() {
            let path_hashes = path_element.siblings;
            let optional_index = path_element.current_selection; // Optional because of Bellman blank-circuit construction mechanics.

            let cs = &mut cs.namespace(|| format!("merkle tree hash {}", i));

            let mut index_bits = Vec::with_capacity(index_bit_count);

            for i in 0..index_bit_count {
                let bit = AllocatedBit::alloc(cs.namespace(|| format!("index bit {}", i)), {
                    optional_index.map(|index| ((index >> i) & 1) == 1)
                })?;

                index_bits.push(Boolean::from(bit));
            }

            auth_path_bits.extend_from_slice(&index_bits);

            // Witness the authentication path elements adjacent at this depth.
            let path_hash_nums = path_hashes
                .iter()
                .enumerate()
                .map(|(i, elt)| {
                    num::AllocatedNum::alloc(cs.namespace(|| format!("path element {}", i)), || {
                        elt.ok_or_else(|| SynthesisError::AssignmentMissing)
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;

            let inserted = insert(cs, &cur, &index_bits, &path_hash_nums)?;

            // Compute the new subtree value
            cur = poseidon_hash(cs, inserted, A::params())?;
        }

        Ok((cur, auth_path_bits))
    }
}
