// Copyright (c) 2019-2020 Web 3 Foundation
//
// Authors:
// - Wei Tang <hi@that.world>
// - Sergey Vasilyev <swasilyev@gmail.com>
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### Ring VRF zkSNARK circut

use ff::Field;
use zcash_primitives::jubjub::{FixedGenerators, JubjubEngine, PrimeOrder, edwards::Point}; // Unknown
use zcash_proofs::circuit::{ecc, pedersen_hash};
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use bellman::gadgets::{boolean, num, Assignment};

use crate::{JubjubEngineWithParams, merkle::MerkleSelection, RingSecretCopath, SecretKey};


/// A circuit for proving that the given vrf_preout is valid for the given vrf_input under
/// a key from the predefined set. It formalizes the following language:
///
/// {(VRF_INPUT, VRF_OUTPUT, set) | VRF_OUTPUT = vrf(sk, VRF_INPUT), PK = derive(sk) and PK is in set }, where:
/// - sk, PK is an elliptic curve keypair, thus PK is a point, sk is a scalar and derive(sk) = sk * B, for a predefined base pont B
/// - VRF_INPUT and VRF_OUTPUT are elliptic curve points, and vrf(sk, VRF_INPUT) = sk * VRF_INPUT
/// - set // TODO
///
/// These are the values that are required to construct the circuit and populate all the wires.
/// They are defined as Options as for CRS generation only circuit structure is relevant,
/// not the wires' assignments, so knowing the types is enough.
pub struct RingVRF<E: JubjubEngine> { // TODO: name
    /// Merkle tree depth
    pub depth: u32,

    /// The secret key, an element of Jubjub scalar field.
    pub sk: Option<SecretKey<E>>,

    /// The VRF input, a point in Jubjub prime order subgroup.
    pub vrf_input: Option<Point<E, PrimeOrder>>,

    /// An extra message to sign along with the 
    pub extra: Option<E::Fr>,

    /// The authentication path of the public key x-coordinate in the Merkle tree,
    /// the element of Jubjub base field.
    /// This is enough to build the root as the base point is hardcoded in the circuit in the lookup tables,
    /// so we can restore the public key from the secret key.
    pub copath: Option<RingSecretCopath<E>>,
}

impl<E: JubjubEngineWithParams> Circuit<E> for RingVRF<E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        if let Some(copath) = self.copath.as_ref() {
            if copath.depth() != self.depth {
                return Err(SynthesisError::Unsatisfiable)
            }
        }

        let engine_params = E::params();

        // Binary representation of the secret key, a prover's private input.
        // fs_bits wires and fs_bits booleanity constraints, where fs_bits = 252 is Jubjub scalar field size.
        // It isn't (range-)constrained to be an element of the field, so small values will have duplicate representations.
        // That doesn't matter for the following reasons: // TODO: double-check
        // 1. Knowledge of a congruence of the secret key is equivalent to the knowledge of the secret key,
        //    and the check sk * G = PK passes for a congruent (sk + n|fs|) * G = sk * G + n|fs| * G == PK + O
        // 2. Multiplication by a congruent secret key results in the same VRF output:
        //    (sk + n|fs|) * H == sk * H, if ord(H) == |fs|
        let sk_bits = boolean::field_into_boolean_vec_le(
            cs.namespace(|| "sk"), self.sk.map(|sk| sk.key)
        ) ?;

        // Derives the public key from the secret key using the hardcoded generator,
        // that is guaranteed to be in the primeorder subgroup,
        // so no on-curve or subgroup checks are required //TODO: double-check
        // 750 constraints according to Zcash spec A.3.3.7
        let pk = ecc::fixed_base_multiplication(
            cs.namespace(|| "PK = sk * G"),
            FixedGenerators::SpendingKeyGenerator, //TODO: any NUMS point of full order
            &sk_bits,
            engine_params,
        ) ?;

        // Defines first 2 public input wires for the coordinates of the public key in Jubjub base field (~ BLS scalar field)
        // and assures their assignment matches the values calculated in the previous step in 2 constraints.
        // These 2 constraints are not strictly required, just Bellman is implemented this way.
        // TODO: x coordinate only
        // pk.inputize(cs.namespace(|| "PK")) ?;

        // Allocates VRF_BASE on the circuit and checks that it is a point on the curve
        // adds 4 constraints (A.3.3.1) to check that it is indeed a point on Jubjub
        let vrf_input = ecc::EdwardsPoint::witness(
            cs.namespace(|| "VRF_INPUT"),
            self.vrf_input,
            engine_params,
        ) ?;

        // Checks that VRF_BASE lies in a proper subgroup of Jubjub. Not strictly required as it is the point provided
        // externally as a public input, so MUST be previously checked by the verifier off-circuit.
        // But why not double-check it in 16 = 3 * 5 (ec doubling) + 1 (!=0) constraints
        // Moreover //TODO
        vrf_input.assert_not_small_order(
            cs.namespace(|| "VRF_BASE not small order"),
            engine_params,
        ) ?;

        // Defines the 3rd and the 4th input wires to be equal VRF_BASE coordinates,
        // thus adding 2 more constraints
        vrf_input.inputize(cs.namespace(|| "VRF_BASE input")) ?;

        // Produces VRF output = sk * VRF_BASE, it is a variable base multiplication, thus
        // 3252 constraints (A.3.3.8)
        // TODO: actually it is 13 more as it is full-length (252 bits) multiplication below
        let vrf = vrf_input.mul(
            cs.namespace(|| "vrf = sk * VRF_BASE"),
            &sk_bits,
            engine_params
        ) ?;

        // And 2 more constraints to verify the output
        vrf.inputize(cs.namespace(|| "vrf")) ?;

        // Add the extra message wire, which consists of one E::Fr scalar.
        // see: https://docs.rs/zcash_proofs/0.2.0/src/zcash_proofs/circuit/ecc.rs.html#138-155
        let owned_extra = self.extra;
        let extra = num::AllocatedNum::alloc(
            cs.namespace(|| "extra message"),
            || Ok(*owned_extra.get()?)
        ) ?;
        extra.inputize(cs.namespace(|| "extra"))?;

        // So the circuit is 6 (public inputs) + 252 (sk booleanity) + 750 (fixed-base mul)
        //                 + 20 (on-curve + subgroup check) + 3252 (var-base mul)
        //                 = 4280 constraints

        // This is an injective encoding, as cur is a
        // point in the prime order subgroup.
        let mut cur = pk.get_x().clone();

        // Ascend the merkle tree authentication path
        for i in 0..(self.depth as usize) {
            let e: Option<(_,_)> = self.copath.as_ref().map(
                |v| ( v.0[i].current_selection, v.0[i].sibling.unwrap_or(<E::Fr>::zero()) )
            );

            let cs = &mut cs.namespace(|| format!("merkle tree hash {}", i));

            // Determines if the current subtree is the "right" leaf at this
            // depth of the tree.
            let cur_is_right = boolean::Boolean::from(boolean::AllocatedBit::alloc(
                cs.namespace(|| "position bit"),
                e.map(|e| e.0 == MerkleSelection::Right),
            ) ?);

            // Witness the authentication path element adjacent
            // at this depth.
            let path_element =
                num::AllocatedNum::alloc(cs.namespace(|| "path element"), || Ok(e.get()?.1)) ?;

            // Swap the two if the current subtree is on the right
            let (xl, xr) = num::AllocatedNum::conditionally_reverse(
                cs.namespace(|| "conditional reversal of preimage"),
                &cur,
                &path_element,
                &cur_is_right,
            ) ?;

            // We don't need to be strict, because the function is
            // collision-resistant. If the prover witnesses a congruency,
            // they will be unable to find an authentication path in the
            // tree with high probability.
            let mut preimage = vec![];
            preimage.extend(xl.to_bits_le(cs.namespace(|| "xl into bits"))?);
            preimage.extend(xr.to_bits_le(cs.namespace(|| "xr into bits"))?);

            // Compute the new subtree value
            cur = pedersen_hash::pedersen_hash(
                cs.namespace(|| "computation of pedersen hash"),
                pedersen_hash::Personalization::MerkleTree(i),
                &preimage,
                engine_params,
            )?.get_x().clone(); // Injective encoding
        }
        cur.inputize(cs.namespace(|| "anchor"))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bellman::gadgets::test::TestConstraintSystem;
    use pairing::bls12_381::Bls12;
    // use zcash_primitives::jubjub::JubjubBls12;

    use rand_core::{RngCore}; // CryptoRng

    use super::*;
    use crate::{JubjubEngineWithParams, VRFInput, RingSecretCopath};

    #[test]
    fn test_ring() {
        let depth = 10;

        // let mut rng = ::rand_chacha::ChaChaRng::from_seed([0u8; 32]);
        let mut rng = ::rand_core::OsRng;

        let sk = SecretKey::<Bls12>::from_rng(&mut rng);
        let pk = sk.to_public();

        let t = crate::signing_context(b"Hello World!").bytes(&rng.next_u64().to_le_bytes()[..]);
        let vrf_input = VRFInput::<Bls12>::new_malleable(t);

        use crate::SigningTranscript;
        let extra = ::merlin::Transcript::new(b"whatever").challenge_scalar(b"");

        let copath = RingSecretCopath::random(depth, &mut rng);
        let auth_root = copath.to_root(&pk);

        let instance = RingVRF {
            depth,
            sk: Some(sk.clone()),
            vrf_input: Some(vrf_input.as_point().clone()),
            extra: Some(extra),
            copath: Some(copath),
        };

        let mut cs = TestConstraintSystem::<Bls12>::new();

        instance.synthesize(&mut cs).unwrap();
        assert!(cs.is_satisfied());
        assert_eq!(cs.num_inputs(), 6 + 1); // the 1st public input predefined to be = 1
        //    assert_eq!(cs.num_constraints(), 4280 + 13); //TODO: 13

        println!("{}", cs.num_constraints() - 4293);

        let vrf_preout = vrf_input.to_preout(&sk); 

        assert_eq!(cs.get_input(1, "VRF_BASE input/x/input variable"), vrf_input.as_point().to_xy().0);
        assert_eq!(cs.get_input(2, "VRF_BASE input/y/input variable"), vrf_input.as_point().to_xy().1);

        assert_eq!(cs.get_input(3, "vrf/x/input variable"), vrf_preout.as_point().to_xy().0);
        assert_eq!(cs.get_input(4, "vrf/y/input variable"), vrf_preout.as_point().to_xy().1);
        assert_eq!(cs.get_input(5, "extra/input variable"), extra );
        assert_eq!(cs.get_input(6, "anchor/input variable"), auth_root.0);
    }
}
