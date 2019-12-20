use std::time::SystemTime;
use std::fs::File;
use bellman::groth16::{Parameters, prepare_verifying_key};
use zcash_primitives::pedersen_hash;
use ff::BitIterator;

pub mod circuit;
pub mod generator;
pub mod prover;
pub mod verifier;

#[test]
fn test_completeness() {
    use ff::{Field, PrimeField};
    use zcash_primitives::jubjub::{JubjubBls12, JubjubParams, PrimeOrder, FixedGenerators, fs, edwards,};
    use pairing::bls12_381::{Bls12, Fr};
    use rand_core::{RngCore, SeedableRng,};
    use rand_xorshift::XorShiftRng;

    let rng = &mut XorShiftRng::from_seed([
        0x58, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let params = &JubjubBls12::new();

    let f = match File::open("crs") {
        Ok(f) => f,
        Err(_) => {
            let mut f = File::create("crs").unwrap();
            let t = SystemTime::now();
            let c = generator::generate_crs().expect("can't generate CRS");
            println!("generation = {}", t.elapsed().unwrap().as_secs());
            c.write(&f);
            f //TODO
        },
    };

    let crs = Parameters::<Bls12>::read(f, false).expect("can't read CRS");

    // Jubjub generator point // TODO: prime or---
    let base_point = params.generator(FixedGenerators::SpendingKeyGenerator);

    // validator's secret key, an element of Jubjub scalar field
    let sk = fs::Fs::random(rng);

    // validator's public key, a point on Jubjub
    let pk = base_point.mul(sk, params);

    // VRF base point
    let vrf_base = edwards::Point::rand(rng, params).mul_by_cofactor(params);

    let vrf_output = vrf_base.mul(sk, params);

    let tree_depth = 10;
    let auth_path = vec![Some((Fr::random(rng), rng.next_u32() % 2 != 0)); tree_depth];

    let mut apk_x = pk.to_xy().0;

    for (i, val) in auth_path.clone().into_iter().enumerate() {
        let (uncle, b) = val.unwrap();

        let mut lhs = apk_x;
        let mut rhs = uncle;

        if b {
            ::std::mem::swap(&mut lhs, &mut rhs);
        }

        let mut lhs: Vec<bool> = BitIterator::new(lhs.into_repr()).collect();
        let mut rhs: Vec<bool> = BitIterator::new(rhs.into_repr()).collect();

        lhs.reverse();
        rhs.reverse();

        apk_x = pedersen_hash::pedersen_hash::<Bls12, _>(
            pedersen_hash::Personalization::MerkleTree(i),
            lhs.into_iter()
                .take(Fr::NUM_BITS as usize)
                .chain(rhs.into_iter().take(Fr::NUM_BITS as usize)),
            params,
        )
            .to_xy()
            .0;
    }


    let t = SystemTime::now();
    let proof = prover::prove(params, &crs, sk, vrf_base.clone(), auth_path.clone());
    println!("proving = {}", t.elapsed().unwrap().as_millis());
    let proof = proof.unwrap();

    let t = SystemTime::now();
    let pvk = prepare_verifying_key::<Bls12>(&crs.vk);
    let valid = verifier::verify(params, &pvk, proof, vrf_base, vrf_output, apk_x);
    println!("verification = {}", t.elapsed().unwrap().as_millis());
    assert_eq!(valid.unwrap(), true);
}
