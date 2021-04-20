// Copyright (c) 2019-2020 Web 3 Foundation
//
// Authors:
// - Wei Tang <hi@that.world>
// - Sergey Vasilyev <swasilyev@gmail.com>
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### Ring VRF zkSNARK circut

use zcash_proofs::circuit::ecc;
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use bellman::gadgets::{boolean, num, Assignment};

use crate::{RingSecretCopath, SecretKey, PoseidonArity, PublicKeyUnblinding, PublicKey};
use neptune::Arity;


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
pub struct RingVRF<A: PoseidonArity> { // TODO: name
    /// Merkle tree depth
    pub depth: u32,

    /// The secret key, an element of Jubjub scalar field.
    // pub sk: Option<SecretKey>,

    // `b_pk` where b_pk is a blinding used to deform the public key in APK = PK + b_pk B,
    // where the 2nd generator B is chosen B = zcash_primitives::constants::NULLIFIER_POSITION_GENERATOR
    // see `SecretKey::dleq_proove` in `dleq` module
    pub unblinding: Option<PublicKeyUnblinding>,

    /// The VRF input, a point in Jubjub prime order subgroup.
    pub pk_blinded: Option<PublicKey>,

    // /// An extra message to sign along with the 
    // pub extra: Option<bls12_381::Scalar>,

    /// The authentication path of the public key x-coordinate in the Merkle tree,
    /// the element of Jubjub base field.
    /// This is enough to build the root as the base point is hardcoded in the circuit in the lookup tables,
    /// so we can restore the public key from the secret key.
    pub copath: RingSecretCopath<A>,
}

impl<A: 'static + PoseidonArity> Circuit<bls12_381::Scalar> for RingVRF<A> {

    fn synthesize<CS: ConstraintSystem<bls12_381::Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        if self.copath.depth() != self.depth {
            return Err(SynthesisError::Unsatisfiable)
        }

        // TODO: update comment
        // Binary representation of the secret key, a prover's private input.
        // fs_bits wires and fs_bits booleanity constraints, where fs_bits = 252 is Jubjub scalar field size.
        // It isn't (range-)constrained to be an element of the field, so small values will have duplicate representations.
        // That doesn't matter for the following reasons: // TODO: double-check
        // 1. Knowledge of a congruence of the secret key is equivalent to the knowledge of the secret key,
        //    and the check sk * G = PK passes for a congruent (sk + n|fs|) * G = sk * G + n|fs| * G == PK + O
        // 2. Multiplication by a congruent secret key results in the same VRF output:
        //    (sk + n|fs|) * H == sk * H, if ord(H) == |fs|

        // -b_pk
        let bp_neg_bits = boolean::field_into_boolean_vec_le(
            cs.namespace(|| "-b_pk"), self.unblinding.map(|x| -x.0)
        ) ?;

        // TODO: update comment
        // Derives the public key from the secret key using the hardcoded generator,
        // that is guaranteed to be in the primeorder subgroup,
        // so no on-curve or subgroup checks are required //TODO: double-check
        // 750 constraints according to Zcash spec A.3.3.7

        // - b_pk B = PK - APK
        let pk_delta = ecc::fixed_base_multiplication(
            cs.namespace(|| "- b_pk B"),
            &zcash_proofs::constants::NULLIFIER_POSITION_GENERATOR, //TODO: any NUMS point of full order
            &bp_neg_bits
        ) ?;

        // TODO: update comment
        // Defines first 2 public input wires for the coordinates of the public key in Jubjub base field (~ BLS scalar field)
        // and assures their assignment matches the values calculated in the previous step in 2 constraints.
        // These 2 constraints are not strictly required, just Bellman is implemented this way.
        // TODO: x coordinate only
        // pk.inputize(cs.namespace(|| "PK")) ?;

        // Allocates VRF_BASE on the circuit and checks that it is a point on the curve
        // adds 4 constraints (A.3.3.1) to check that it is indeed a point on Jubjub

        // APK
        let pk_blinded = ecc::EdwardsPoint::witness(
            cs.namespace(|| "VRF_INPUT"),
            self.pk_blinded.map(|p| p.0)
        ) ?;

        // Checks that VRF_BASE lies in a proper subgroup of Jubjub. Not strictly required as it is the point provided
        // externally as a public input, so MUST be previously checked by the verifier off-circuit.
        // But why not double-check it in 16 = 3 * 5 (ec doubling) + 1 (!=0) constraints
        // Moreover //TODO
        pk_blinded.assert_not_small_order(
            cs.namespace(|| "VRF_BASE not small order")
        ) ?;

        // Defines the 3rd and the 4th input wires to be equal VRF_BASE coordinates,
        // thus adding 2 more constraints
        pk_blinded.inputize(cs.namespace(|| "APK")) ?;

        // Produces VRF output = sk * VRF_BASE, it is a variable base multiplication, thus
        // 3252 constraints (A.3.3.8)
        // TODO: actually it is 13 more as it is full-length (252 bits) multiplication below


        // APK + pk_delta = APK + (PK - APK) = PK
        let pk = pk_blinded.add(
            cs.namespace(|| "PK = APK + pk_delta"),
            &pk_delta
        ) ?;

        // // And 2 more constraints to verify the output
        // pk.inputize(cs.namespace(|| "vrf")) ?;

        /*
        // Add the extra message wire, which consists of one E::Fr scalar.
        // see: https://docs.rs/zcash_proofs/0.2.0/src/zcash_proofs/circuit/ecc.rs.html#138-155
        let owned_extra = self.extra;
        let extra = num::AllocatedNum::alloc(
            cs.namespace(|| "extra message"),
            || Ok(*owned_extra.get()?)
        ) ?;
        extra.inputize(cs.namespace(|| "extra"))?;
        */

        // So the circuit is 6 (public inputs) + 252 (sk booleanity) + 750 (fixed-base mul)
        //                 + 20 (on-curve + subgroup check) + 3252 (var-base mul)
        //                 = 4280 constraints

        // This is an injective encoding, as cur is a
        // point in the prime order subgroup.
        let cur = pk.get_u().clone();

        let (cur, _) = self.copath.synthesize(cs.namespace(|| "Merkle tree"), cur)?;
        cur.inputize(cs.namespace(|| "anchor"))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bellman::gadgets::test::TestConstraintSystem;

    use rand_core::{RngCore};
    use group::Curve;

    use super::*;
    use crate::{VRFInput, RingSecretCopath};
    use typenum::U4;

    #[test]
    fn test_ring() {
        use crate::vrf::{VRFMalleability}; // Malleable
        use crate::dleq::{VRFSignature, PedersenDelta};

        let depth = 9;

        // let mut rng = ::rand_chacha::ChaChaRng::from_seed([0u8; 32]);
        let mut rng = ::rand_core::OsRng;

        let sk = SecretKey::from_rng(&mut rng);
        let pk = sk.to_public();

        let input = crate::signing_context(b"Hello World!").bytes(&rng.next_u64().to_le_bytes()[..]);
        // Malleable::vrf_input(input);

        let copath = RingSecretCopath::<U4>::random(depth, &mut rng);
        let auth_root = copath.to_root(&pk);
        let inout = copath.to_root(&pk).vrf_input(input).to_inout(&sk);
        let (proof, unblinding): (VRFSignature<PedersenDelta>, PublicKeyUnblinding)
          = sk.dleq_proove(&inout, crate::no_extra(), &mut rng);

        let instance = RingVRF {
            depth,
            unblinding: Some(unblinding),
            pk_blinded: Some(proof.publickey().clone()),
            // extra: Some(extra),
            copath: copath,
        };

        let mut cs = TestConstraintSystem::new();

        instance.synthesize(&mut cs).unwrap();
        assert!(cs.is_satisfied());
        assert_eq!(cs.num_inputs(), 3 + 1); // the 1st public input predefined to be = 1
        //    assert_eq!(cs.num_constraints(), 4280 + 13); //TODO: 13

        println!("{}", cs.num_constraints());

        assert_eq!(cs.get_input(1, "APK/u/input variable"), proof.publickey().0.to_affine().get_u());
        assert_eq!(cs.get_input(2, "APK/v/input variable"), proof.publickey().0.to_affine().get_v());
        // assert_eq!(cs.get_input(3, "extra/input variable"), extra);
        assert_eq!(cs.get_input(3, "anchor/input variable"), auth_root.0);
    }
}
