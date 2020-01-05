use ff::{Field, PrimeField, PrimeFieldRepr, BitIterator};

use bellman::{Circuit, ConstraintSystem, SynthesisError};

use zcash_primitives::jubjub::{FixedGenerators, JubjubEngine, edwards, PrimeOrder, JubjubParams};

use zcash_primitives::constants;

use zcash_primitives::primitives::{PaymentAddress, ProofGenerationKey, ValueCommitment};

use zcash_proofs::circuit::ecc;
use zcash_proofs::circuit::pedersen_hash;
use bellman::gadgets::blake2s;
use bellman::gadgets::boolean;
use bellman::gadgets::multipack;
use bellman::gadgets::num;
use bellman::gadgets::Assignment;
use bellman::gadgets::test::TestConstraintSystem;
use pairing::bls12_381::Bls12;

// A circuit for proving that the given vrf_output is valid for the given vrf_input under
// a key from the predefined set. It formalizes the following language:
// {(VRF_INPUT, VRF_OUTPUT, set) | VRF_OUTPUT = vrf(sk, VRF_INPUT), PK = derive(sk) and  PK is in set }, where:
// - sk, PK is an elliptic curve keypair, thus PK is a point, sk is a scalar and derive(sk) = sk * B, for a predefined base pont B
// - VRF_INPUT and VRF_OUTPUT are elliptic curve points, and vrf(sk, VRF_INPUT) = sk * VRF_INPUT
// - set //TODO

// These are the values that are required to construct the circuit and populate all the wires.
// They are defined as Options as for CRS generation only circuit structure is relevant,
// not the wires' assignments, so knowing the types is enough.
pub struct Ring<'a, E: JubjubEngine> { // TODO: name

    // Jubjub curve parameters.
    pub params: &'a E::Params,

    // The secret key, an element of Jubjub scalar field.
    pub sk: Option<E::Fs>,

    // The VRF input, a point in Jubjub prime order subgroup.
    pub vrf_input: Option<edwards::Point<E, PrimeOrder>>,

    // The authentication path of the public key x-coordinate in the Merkle tree,
    // the element of Jubjub base field.
    // This is enough to build the root as the base point is hardcoded in the circuit in the lookup tables,
    // so we can restore the public key from the secret key.
    pub auth_path: Vec<Option<(E::Fr, bool)>>,
}

impl<'a, E: JubjubEngine> Circuit<E> for Ring<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Binary representation of the secret key, a prover's private input.
        // fs_bits wires and fs_bits booleanity constraints, where fs_bits = 252 is Jubjub scalar field size.
        // It isn't (range-)constrained to be an element of the field, so small values will have duplicate representations.
        // That doesn't matter for the following reasons: // TODO: double-check
        // 1. Knowledge of a congruence of the secret key is equivalent to the knowledge of the secret key,
        //    and the check sk * G = PK passes for a congruent (sk + n|fs|) * G = sk * G + n|fs| * G == PK + O
        // 2. Multiplication by a congruent secret key results in the same VRF output:
        //    (sk + n|fs|) * H == sk * H, if ord(H) == |fs|
        let sk_bits = boolean::field_into_boolean_vec_le(cs.namespace(|| "sk"), self.sk)?;

        // Derives the public key from the secret key using the hardcoded generator,
        // that is guaranteed to be in the primeorder subgroup,
        // so no on-curve or subgroup checks are required //TODO: double-check
        // 750 constraints according to Zcash spec A.3.3.7
        let pk = ecc::fixed_base_multiplication(
            cs.namespace(|| "PK = sk * G"),
            FixedGenerators::SpendingKeyGenerator, //TODO: any NUMS point of full order
            &sk_bits,
            self.params,
        )?;
//
//        // Defines first 2 public input wires for the coordinates of the public key in Jubjub base field (~ BLS scalar field)
//        // and assures their assignment matches the values calculated in the previous step in 2 constraints.
//        // These 2 constraints are not strictly required, just Bellman is implemented this way.
//        // TODO: x coordinate only
//        pk.inputize(cs.namespace(|| "PK"))?;

        // Allocates VRF_BASE on the circuit and checks that it is a point on the curve
        // adds 4 constraints (A.3.3.1) to check that it is indeed a point on Jubjub
        let vrf_input = ecc::EdwardsPoint::witness(
            cs.namespace(|| "VRF_INPUT"),
            self.vrf_input,
            self.params,
        )?;

        // Checks that VRF_BASE lies in a proper subgroup of Jubjub. Not strictly required as it is the point provided
        // externally as a public input, so MUST be previously checked by the verifier off-circuit.
        // But why not double-check it in 16 = 3 * 5 (ec doubling) + 1 (!=0) constraints
        // Moreover //TODO
        vrf_input.assert_not_small_order(cs.namespace(|| "VRF_BASE not small order"), self.params)?;

        // Defines the 3rd and the 4th input wires to be equal VRF_BASE coordinates,
        // thus adding 2 more constraints
        vrf_input.inputize(cs.namespace(|| "VRF_BASE input"))?;

        // Produces VRF output = sk * VRF_BASE, it is a variable base multiplication, thus
        // 3252 constraints (A.3.3.8)
        // TODO: actually it is 13 more as it is full-length (252 bits) multiplication below
        let vrf = vrf_input.mul(cs.namespace(|| "vrf = sk * VRF_BASE"), &sk_bits, self.params)?;

        // And 2 more constraints to verify the output
        vrf.inputize(cs.namespace(|| "vrf"))?;

        // So the circuit is 6 (public inputs) + 252 (sk booleanity) + 750 (fixed-base mul)
        //                 + 20 (on-curve + subgroup check) + 3252 (var-base mul)
        //                 = 4280 constraints

        // This is an injective encoding, as cur is a
        // point in the prime order subgroup.
        let mut cur = pk.get_x().clone();

        // Ascend the merkle tree authentication path
        for (i, e) in self.auth_path.into_iter().enumerate() {
            let cs = &mut cs.namespace(|| format!("merkle tree hash {}", i));

            // Determines if the current subtree is the "right" leaf at this
            // depth of the tree.
            let cur_is_right = boolean::Boolean::from(boolean::AllocatedBit::alloc(
                cs.namespace(|| "position bit"),
                e.map(|e| e.1),
            )?);

            // Witness the authentication path element adjacent
            // at this depth.
            let path_element =
                num::AllocatedNum::alloc(cs.namespace(|| "path element"), || Ok(e.get()?.0))?;

            // Swap the two if the current subtree is on the right
            let (xl, xr) = num::AllocatedNum::conditionally_reverse(
                cs.namespace(|| "conditional reversal of preimage"),
                &cur,
                &path_element,
                &cur_is_right,
            )?;

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
                self.params,
            )?
                .get_x()
                .clone(); // Injective encoding
        }
        cur.inputize(cs.namespace(|| "anchor"))?;
        Ok(())
    }
}

#[test]
fn test_ring() {
    use bellman::gadgets::test::TestConstraintSystem;
    use pairing::bls12_381::{Bls12, Fr,};
    use zcash_primitives::pedersen_hash;
    use zcash_primitives::jubjub::{JubjubBls12, fs, edwards,};
    use rand_core::{RngCore, SeedableRng,};
    use rand_xorshift::XorShiftRng;

    let params = &JubjubBls12::new();

    let rng = &mut XorShiftRng::from_seed([
        0x58, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let sk = fs::Fs::random(rng);

    let vrf_base = edwards::Point::rand(rng, params).mul_by_cofactor(params);
    let base_point = params.generator(FixedGenerators::SpendingKeyGenerator);
    let pk = base_point.mul(sk, params).to_xy();

    let tree_depth = 10;
    let auth_path = vec![Some((Fr::random(rng), rng.next_u32() % 2 != 0)); tree_depth];

    let mut cur = pk.0;

    for (i, val) in auth_path.clone().into_iter().enumerate() {
        let (uncle, b) = val.unwrap();

        let mut lhs = cur;
        let mut rhs = uncle;

        if b {
            ::std::mem::swap(&mut lhs, &mut rhs);
        }

        let mut lhs: Vec<bool> = BitIterator::new(lhs.into_repr()).collect();
        let mut rhs: Vec<bool> = BitIterator::new(rhs.into_repr()).collect();

        lhs.reverse();
        rhs.reverse();

        cur = pedersen_hash::pedersen_hash::<Bls12, _>(
            pedersen_hash::Personalization::MerkleTree(i),
            lhs.into_iter()
                .take(Fr::NUM_BITS as usize)
                .chain(rhs.into_iter().take(Fr::NUM_BITS as usize)),
            params,
        )
            .to_xy()
            .0;
    }

    let instance = Ring {
        params,
        sk: Some(sk),
        vrf_input: Some(vrf_base.clone()),
        auth_path:  auth_path.clone(),
    };

    let mut cs = TestConstraintSystem::<Bls12>::new();

    instance.synthesize(&mut cs).unwrap();
    assert!(cs.is_satisfied());
    assert_eq!(cs.num_inputs(), 5 + 1); // the 1st public input predefined to be = 1
//    assert_eq!(cs.num_constraints(), 4280 + 13); //TODO: 13

    println!("{}", cs.num_constraints() - 4293);

    assert_eq!(cs.get_input(1, "VRF_BASE input/x/input variable"), vrf_base.to_xy().0);
    assert_eq!(cs.get_input(2, "VRF_BASE input/y/input variable"), vrf_base.to_xy().1);

    let vrf = vrf_base.mul(sk, params).to_xy();
    assert_eq!(cs.get_input(3, "vrf/x/input variable"), vrf.0);
    assert_eq!(cs.get_input(4, "vrf/y/input variable"), vrf.1);
    assert_eq!(cs.get_input(5, "anchor/input variable"), cur);
}