use merlin::Transcript;

use crate::{SigningTranscript, vrf, Signature};

use ark_std::vec::Vec;


type K = ark_bls12_377::G1Affine;
// type H = ark_bls12_377::G1Affine;

// ark_ed_on_bls12_377::G1Affine

// type ThinVrf = crate::ThinVrf<K>;
type PedersenVrf = crate::PedersenVrf<K>;
type SecretKey = crate::SecretKey<K>;


pub(crate) fn pedersen_vrf_test_flavor() -> PedersenVrf {
    let mut t = Transcript::new(b"TestFlavor");
    PedersenVrf::new(
        t.challenge(b"Keying"),
        [t.challenge(b"Blinding")],
    )
}

#[test]
fn master() {
    let flavor = pedersen_vrf_test_flavor();
    let sk = SecretKey::new((*flavor).clone());

    let mk_io = |n| {
        let mut t = Transcript::new(b"VrfIO");
        t.append_u64(b"n",n);
        sk.vrf_inout_from_transcript(t)
    };
    let ios: [vrf::VrfInOut<K>; 4] = [mk_io(0), mk_io(1), mk_io(2), mk_io(3)];
    let rng = &mut rand_core::OsRng;

    let t = Transcript::new(b"AD1");
    let sig_thin = sk.sign_thin_vrf(t, &ios[0..2], rng);

    let t = Transcript::new(b"AD2");
    let (sig_pedersen, secret_blinding)
     = flavor.sign_pedersen_vrf(t, &ios[1..], None, &sk, rng);
    assert!( *sig_pedersen.as_key_commitment() == flavor.compute_blinded_publickey(sk.as_publickey(),&secret_blinding) );

    let t = Transcript::new(b"AD3");
    let sig_non_batchable
     = flavor.sign_non_batchable_pedersen_vrf(t, &ios[2..], None, &sk, rng).0;
    
    let mut buf = Vec::new();
    sig_pedersen.serialize(&mut buf).unwrap();
    let sig_pedersen = Signature::deserialize(buf.as_ref()).unwrap();
    buf.clear();
    sig_thin.serialize(&mut buf).unwrap();
    let sig_thin = Signature::deserialize(buf.as_ref()).unwrap();

    let t = Transcript::new(b"AD1");
    flavor.verify_thin_vrf(t, &ios[0..2], sk.as_publickey(), &sig_thin).unwrap();
    let t = Transcript::new(b"AD1");
    flavor.verify_thin_vrf(t, &ios[0..3], sk.as_publickey(), &sig_thin).expect_err("WTF?!?");

    let t = Transcript::new(b"AD2");
    flavor.verify_pedersen_vrf(t, &ios[1..], &sig_pedersen).unwrap();
    let t = Transcript::new(b"AD2");
    flavor.verify_pedersen_vrf(t, &ios[2..], &sig_pedersen).expect_err("WTF?!?");

    let t = Transcript::new(b"AD3");
    flavor.verify_non_batchable_pedersen_vrf(t, &ios[2..], &sig_non_batchable).unwrap();

}

