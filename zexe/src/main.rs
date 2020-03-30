use crypto_primitives::{crh::{
    pedersen::{constraints::PedersenCRHGadget, PedersenCRH, PedersenWindow},
    FixedLengthCRH, FixedLengthCRHGadget,
}, merkle_tree::{MerkleTreePath, MerkleHashTree, MerkleTreeConfig}, MerkleTreePathGadget};
use algebra::jubjub::{Fq, JubJubAffine as JubJub};
use r1cs_core::{ConstraintSystem, SynthesisError, ConstraintSynthesizer};
use r1cs_std::prelude::*;
use r1cs_std::{jubjub::JubJubGadget};
use crypto_primitives::crh::pedersen::PedersenParameters;


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


struct RingVRF<'a> {
    crh_params: PedersenParameters<JubJub>,
    auth_path: JubJubMerklePath,
    root: <PedersenCRH<JubJub, Window4x256> as FixedLengthCRH>::Output,
    leaf: &'a [u8; 30]
}

impl<'a> ConstraintSynthesizer<Fq> for RingVRF<'a> {
    fn generate_constraints<CS: ConstraintSystem<Fq>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let crh_params = <HG as FixedLengthCRHGadget<H, Fq>>::ParametersGadget::alloc(
            &mut cs.ns(|| "crh_params"),
            || Ok(self.crh_params.clone())
        ).unwrap();



        let root = <HG as FixedLengthCRHGadget<H, _>>::OutputGadget::alloc_input(
            &mut cs.ns(|| "root"),
            || Ok(self.root.clone())
        ).unwrap();

        let path = MerkleTreePathGadget::<_, HG, _>::alloc(
            &mut cs.ns(|| "path"),
            || Ok(self.auth_path.clone())
        ).unwrap();

        let leaf = UInt8::constant_vec(self.leaf);

        path.check_membership(
            &mut cs.ns(|| "path verification"),
            &crh_params,
            &root,
            &leaf.as_slice()
        );

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

    let rng = &mut test_rng();

    let mut leaves = Vec::new();
    for i in 0..4u8 {
        let input = [i; 30];
        leaves.push(input);
    }

    let i = 2;
    let leaf = leaves[i];

    let crh_params = H::setup(rng).unwrap();
    let tree = JubJubMerkleTree::new(crh_params.clone(), &leaves).unwrap();
    let root = tree.root();


    let proof = tree.generate_proof(i, &leaf).unwrap();
    assert!(proof.verify(&crh_params, &root, &leaf).unwrap());

    let c = RingVRF {
        crh_params: crh_params.clone(),
        auth_path: proof.clone(),
        root,
        leaf: &leaf
    };
    let params = generate_random_parameters::<Bls12_381, _, _>(c, rng).unwrap();

    let c = RingVRF {
        crh_params,
        auth_path: proof,
        root,
        leaf: &leaf
    };
    let pvk = prepare_verifying_key(&params.vk);
    let proof = create_random_proof(c, &params, rng).unwrap();
    assert!(verify_proof(&pvk, &proof, &[root.x, root.y]).unwrap());
}