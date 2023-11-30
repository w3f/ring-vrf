
use dleq_vrf::Transcript;

use ark_serialize::{CanonicalSerialize,CanonicalDeserialize};
use ark_std::vec::Vec;

use crate::bls12_381::*;

#[test]
fn single() {
    let sk = SecretKey::ephemeral();

    let mut buf = Vec::new();
    let pk0 = sk.create_nugget_public();
    pk0.serialize_compressed(&mut buf).unwrap();
    let pk = AggregationKey::deserialize_compressed::<&[u8]>(buf.as_slice()).unwrap();
    assert_eq!(pk0,pk);
    pk.validate_nugget_public().unwrap();
    assert_eq!(sk.to_g1_publickey(), pk.to_g1_publickey());

    let domain = b"";
    let message = b"MSG1";
    let t = Transcript::new_labeled(b"AD1");
    let input = Message { domain, message };
    let signature = sk.sign_nugget_bls(t,input); 

    buf.clear();
    signature.serialize_compressed(&mut buf).unwrap();
    let signature = Signature::deserialize_compressed::<&[u8]>(buf.as_slice()).unwrap();

    let t = Transcript::new_labeled(b"AD1");
    let msg = Message { domain, message };
    pk.verify_nugget_bls(t,msg,&signature).unwrap();
}

#[test]
fn aggregation() {
    let domain = b"";
    let message = b"MSG";
    let sks: Vec<SecretKey> = (0..2).map(|_| SecretKey::ephemeral()).collect();
    let pks: Vec<AggregationKey> = sks.iter().map(|sk| sk.create_nugget_public()).collect();
    let mut g1pks0 = Vec::new();
    let sigs: Vec<Signature> = sks.iter().map(|sk| {
        g1pks0.push(sk.to_g1_publickey());
        let mut t = Transcript::new_labeled(b"AD");
        t.append(&sk.to_g1_publickey());
        let input = Message { domain, message };
        sk.sign_nugget_bls(t,input)
    }).collect();
    let agg = crate::AggregateSignature::create(&pks, &sigs);
    let input = Message { domain, message };
    let g1pks: Vec<_> = pks.iter().map(|pk| pk.to_g1_publickey()).collect();
    assert_eq!(g1pks0, g1pks);
    agg.verify_by_pks(input,g1pks.iter()).unwrap();
}

