use algebra::jubjub::{Fq, JubJubAffine as JubJub};
use algebra_core::{BitIterator, Group, UniformRand};
use algebra_core::fields::{FpParameters, PrimeField};
use crypto_primitives::crh::{FixedLengthCRH,FixedLengthCRHGadget};
use crypto_primitives::crh::pedersen::{PedersenParameters, PedersenCRH, PedersenWindow};
use crypto_primitives::crh::pedersen::constraints::PedersenCRHGadget;
use crypto_primitives::merkle_tree::{MerkleHashTree, MerkleTreeConfig, MerkleTreePath};
use crypto_primitives::merkle_tree::constraints::MerkleTreePathGadget;
use r1cs_core::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use r1cs_std::prelude::*;
use r1cs_std::{jubjub::JubJubGadget};
use r1cs_std::groups::GroupGadget;

#[derive(Clone)]
struct Window4x256;

impl PedersenWindow for Window4x256 {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 256;
}

type H = PedersenCRH<JubJub, Window4x256>;
type HG = PedersenCRHGadget<JubJub, Fq, JubJubGadget>;

struct JubJubMerkleTreeParams;

impl MerkleTreeConfig for JubJubMerkleTreeParams {
    const HEIGHT: usize = 4;
    type H = H;
}

type JubJubMerkleTree = MerkleHashTree<JubJubMerkleTreeParams>;
type JubJubMerklePath = MerkleTreePath<JubJubMerkleTreeParams>;

type Scalar = <JubJub as Group>::ScalarField;

// TODO: make it a gadget?
#[derive(Clone)]
struct RingVRF {
    sk: Scalar,
    base_point_powers: Vec<JubJub>,
    vrf_input: JubJub,
    crh_params: PedersenParameters<JubJub>,
    auth_path: JubJubMerklePath,
    root: <PedersenCRH<JubJub, Window4x256> as FixedLengthCRH>::Output,
}

impl ConstraintSynthesizer<Fq> for RingVRF {
    fn generate_constraints<CS: ConstraintSystem<Fq>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let mut constraint_count = cs.num_constraints();

        // witness signer's secret key as a sequence of bits starting from the least significant one
        let mut sk_bits: Vec<bool> = BitIterator::new(self.sk.into_repr()).collect();
        sk_bits.reverse();
        let sk_bits = Vec::<Boolean>::alloc(
            cs.ns(|| "sk_bits"),
            || Ok(sk_bits)
        )?;

        // constraint_count = <Scalar as PrimeField>::Params::MODULUS_BITS as usize;
        // though Jujubjub scalar field element fits 252 bits, Zexe represents it in 256 bits
        // TODO:  constraint redundant bits to zero?
        constraint_count += 256;  // 256 booleanity constraints
        assert_eq!(cs.num_constraints(), constraint_count);

        let vrf_input = JubJubGadget::alloc_input(
            &mut cs.ns(|| "vrf_input"),
            || Ok(self.vrf_input)
        )?;
        constraint_count += 3; // to check that the point lies on Jubjub
        assert_eq!(cs.num_constraints(), constraint_count);
        // TODO: subgroup check

        // addition law for Jubjub is complete, see comment for GroupGadget::mul_bits
        let zero = <JubJubGadget as GroupGadget<JubJub, Fq>>::zero(cs.ns(|| "zero1"))?;
        // TODO: why doesn't infer?
        // let computed_vrf_output = vrf_input.mul_bits(cs.ns(|| "computed_vrf_output"), &zero, sk_bits.iter())?;
        let computed_vrf_output = <JubJubGadget as GroupGadget<JubJub, Fq>>::mul_bits(
            &vrf_input,
            cs.ns(|| "computed_vrf_output"),
            &zero,
            sk_bits.iter()
        )?;
        constraint_count += 256 * (2 + 5 + 6);
        // for each bit:
        // 2 constraints -- point selection (x and y)
        // 5 constraints -- doubling
        // 6 constraints -- addition
        assert_eq!(cs.num_constraints(), constraint_count);

        let expected_vrf_output = JubJubGadget::alloc_input(
            &mut cs.ns(|| "expected_vrf_output"),
            || Ok(<JubJubGadget as GroupGadget<JubJub, Fq>>::get_value(&computed_vrf_output).unwrap_or_default())
        )?;
        constraint_count += 3; // (redundant) subgroup check
        assert_eq!(cs.num_constraints(), constraint_count);

        computed_vrf_output.enforce_equal(
            &mut cs.ns(|| "computed_vrf_output = expected_vrf_output"),
            &expected_vrf_output,
        )?;
        constraint_count += 2; // coordinates equality
        assert_eq!(cs.num_constraints(), constraint_count);

//        Varial base scalar multiplication for PK = sk * BP
//
//        let base_point = JubJubGadget::alloc_input(
//            &mut cs.ns(|| "base_point"),
//            || Ok(self.base_point)
//        )?;
//        constraint_count += 3; // to check that the point lies on Jubjub
//        assert_eq!(cs.num_constraints(), constraint_count);
//
//        let zero = <JubJubGadget as GroupGadget<JubJub, Fq>>::zero(cs.ns(|| "zero2"))?;
//        let pk = <JubJubGadget as GroupGadget<JubJub, Fq>>::mul_bits(
//            &base_point,
//            cs.ns(|| "pk"),
//            &zero,
//            sk_bits.iter()
//        )?;
//        constraint_count += 256 * (2 + 5 + 6);
//        assert_eq!(cs.num_constraints(), constraint_count);

//        assert_eq!(sk_bits.len(), self.base_point_powers.len());
        let mut pk = <JubJubGadget as GroupGadget<JubJub, Fq>>::zero(cs.ns(|| "pk"))?;
        <JubJubGadget as GroupGadget<JubJub, Fq>>::precomputed_base_scalar_mul(
            &mut pk,
            cs.ns(|| "pk = sk * G"),
            sk_bits.iter().zip(&self.base_point_powers)
        )?;
        constraint_count += 252 * 5;
        assert_eq!(cs.num_constraints(), constraint_count);

        let crh_params = <HG as FixedLengthCRHGadget<H, Fq>>::ParametersGadget::alloc(
            &mut cs.ns(|| "crh_params"),
            || Ok(self.crh_params.clone())
        )?;

        let root = <HG as FixedLengthCRHGadget<H, _>>::OutputGadget::alloc_input(
            &mut cs.ns(|| "root"),
            || Ok(self.root.clone())
        )?;

        let path = MerkleTreePathGadget::<_, HG, _>::alloc(
            &mut cs.ns(|| "path"),
            || Ok(self.auth_path.clone())
        )?;

        path.check_membership(
            &mut cs.ns(|| "path verification"),
            &crh_params,
            &root,
            &pk
        )?;

        //TODO: add Jeffs magic wire

        Ok(())
    }
}

#[test]
fn test_tree() {
    use algebra::bls12_381::Bls12_381;
    use algebra_core::test_rng;
    use groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    };
    use r1cs_std::test_constraint_system::TestConstraintSystem;

    let rng = &mut test_rng();

    let sk: <JubJub as Group>::ScalarField = UniformRand::rand(rng);
    let vrf_input: JubJub = UniformRand::rand(rng);

    let num_powers = <Scalar as PrimeField>::Params::MODULUS_BITS as usize;
    let base_point_powers= PedersenCRH::<_, Window4x256>::generator_powers(num_powers, rng);
    let base_point: JubJub = base_point_powers[0];

    let vrf_output = vrf_input.mul(&sk);
    let pk = base_point.mul(&sk);

    let mut leaves = vec![];
    leaves.resize_with(4, || UniformRand::rand(rng));

    let i = 2;
    leaves[i] = pk;

    let crh_params = H::setup(rng).unwrap();
    let tree = JubJubMerkleTree::new(crh_params.clone(), &leaves).unwrap();
    let root = tree.root();

    let auth_path = tree.generate_proof(i, &pk).unwrap();
    assert!(auth_path.verify(&crh_params, &root, &pk).unwrap());

    let c = RingVRF {
        sk,
        vrf_input,
        base_point_powers,
        crh_params,
        auth_path,
        root
    };

    let mut cs = TestConstraintSystem::<Fq>::new();
    assert!(c.clone().generate_constraints(&mut cs).is_ok());
    if !cs.is_satisfied() {
        println!("{:?}", cs.which_is_unsatisfied().unwrap());
    }
    assert!(cs.is_satisfied());

    let params = generate_random_parameters::<Bls12_381, _, _>(c.clone(), rng).unwrap();
    let pvk = prepare_verifying_key(&params.vk);
    let proof = create_random_proof(c, &params, rng).unwrap();

    assert!(verify_proof(&pvk, &proof, &[vrf_input.x, vrf_input.y, vrf_output.x, vrf_output.y, root.x, root.y]).unwrap());
}