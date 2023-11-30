
use ark_serialize::{CanonicalSerialize,CanonicalDeserialize};
use ark_std::vec::Vec;

use crate::{Transcript, vrf, Batchable};

use ark_bls12_377 as curve;

type K = curve::G1Affine;

type H2C = ark_ec::hashing::map_to_curve_hasher::MapToCurveBasedHasher::<
    <K as ark_ec::AffineRepr>::Group,
    ark_ff::fields::field_hashers::DefaultFieldHasher<sha2::Sha256>,
    ark_ec::hashing::curve_maps::wb::WBMap<curve::g1::Config>,
>;

type PedersenVrf = crate::PedersenVrf<K>;

pub(crate) fn pedersen_vrf_test_flavor() -> PedersenVrf {
    let mut t = Transcript::new_labeled(b"TestFlavor");
    let mut reader = t.challenge(b"Keying&Blinding");
    crate::ThinVrf { keying_base: reader.read_uniform(), }
    .pedersen_vrf([ reader.read_uniform() ])
}


#[test]
fn master() {
    let flavor = pedersen_vrf_test_flavor();
    let mut sk = (*flavor).clone().ephemeral_secretkey();

    let mk_io = |n: u32| {
        let input = vrf::ark_hash_to_curve::<K,H2C>(b"VrfIO",&n.to_le_bytes()[..]).unwrap();
        sk.vrf_inout(input)
    };
    let ios: [vrf::VrfInOut<K>; 4] = [mk_io(0), mk_io(1), mk_io(2), mk_io(3)];

    let t = Transcript::new_labeled(b"AD1");
    let sig_thin = sk.sign_thin_vrf_detached(t, &ios[0..2]);

    let t = Transcript::new_labeled(b"AD2");
    let (sig_pedersen, secret_blinding)
     = flavor.sign_pedersen_vrf(t, &ios[1..], None, &mut sk);
     assert!( *sig_pedersen.as_key_commitment() == flavor.compute_blinded_publickey(sk.as_publickey(),&secret_blinding) );

    let t = Transcript::new_labeled(b"AD3");
    let sig_non_batchable
     = flavor.sign_non_batchable_pedersen_vrf(t, &ios[2..], None, &mut sk).0;
    
    let mut buf = Vec::new();
    sig_pedersen.serialize_compressed(&mut buf).unwrap();
    let sig_pedersen = Batchable::deserialize_compressed::<&[u8]>(buf.as_slice()).unwrap();

    buf.clear();
    sig_thin.serialize_compressed(&mut buf).unwrap();
    let sig_thin = Batchable::deserialize_compressed::<&[u8]>(buf.as_slice()).unwrap();

    buf.clear();
    sk.as_publickey().serialize_compressed(&mut buf).unwrap();
    let pk = crate::PublicKey::deserialize_compressed::<&[u8]>(buf.as_slice()).unwrap();
    assert!( *sig_pedersen.as_key_commitment() == flavor.compute_blinded_publickey(&pk,&secret_blinding) );

    let t = Transcript::new_labeled(b"AD1");
    flavor.verify_thin_vrf(t, &ios[0..2], &pk, &sig_thin).unwrap();
    let t = Transcript::new_labeled(b"AD1");
    flavor.verify_thin_vrf(t, &ios[0..3], &pk, &sig_thin).expect_err("WTF?!?");

    let t = Transcript::new_labeled(b"AD2");
    flavor.verify_pedersen_vrf(t, &ios[1..], &sig_pedersen).unwrap();
    let t = Transcript::new_labeled(b"AD2");
    flavor.verify_pedersen_vrf(t, &ios[2..], &sig_pedersen).expect_err("WTF?!?");

    let t = Transcript::new_labeled(b"AD3");
    flavor.verify_non_batchable_pedersen_vrf(t, &ios[2..], &sig_non_batchable).unwrap();

}

