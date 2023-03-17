
use merlin::Transcript;

use ark_serialize::{CanonicalSerialize,CanonicalDeserialize};
use ark_std::vec::Vec;

use crate::{SigningTranscript}; // {SecretKey, PublicKey, Signature,};

type P = ark_bls12_381::Bls12_381;
type SecretKey = crate::SecretKey<P>;
type PublicKey = crate::PublicKey<P>;
type Signature = crate::Signature<P>;



#[test]
fn single() {
    let mut rng = &mut rand_core::OsRng;

    let sk = SecretKey::ephemeral();

    let mut buf = Vec::new();
    let pk0 = sk.create_nugget_public();
    pk0.serialize_compressed(&mut buf).unwrap();
    let pk = PublicKey::deserialize_compressed(buf.as_ref()).unwrap();
    assert_eq!(pk0,pk);
    pk.validate_nugget_public().unwrap();
    assert_eq!(sk.as_g1_publickey(), &pk.to_g1_publickey());

    let t = Transcript::new(b"AD1");
    let input = &mut Transcript::new(b"MSG1");
    let signature = sk.sign_nugget_bls(t,input); 

    buf.clear();
    signature.serialize_compressed(&mut buf).unwrap();
    let signature = Signature::deserialize_compressed(buf.as_ref()).unwrap();

    let t = Transcript::new(b"AD1");
    let msg = &mut Transcript::new(b"MSG1");
    pk.verify_nugget_bls(t,msg,&signature).unwrap();
}

#[test]
fn aggregation() {
    let mut rng = &mut rand_core::OsRng;

    let sks: Vec<SecretKey> = (0..2).map(|_| SecretKey::ephemeral()).collect();
    let pks: Vec<PublicKey> = sks.iter().map(|sk| sk.create_nugget_public()).collect();
    let mut g1pks0 = Vec::new();
    let sigs: Vec<Signature> = sks.iter().map(|sk| {
        g1pks0.push(sk.as_g1_publickey().clone());
        let mut t = Transcript::new(b"AD");
        t.append(b"", sk.as_g1_publickey());
        let input = &mut Transcript::new(b"MSG");
        sk.sign_nugget_bls(t,input)
    }).collect();
    let agg = crate::AggregateSignature::create(&pks, &sigs);
    let input = &mut Transcript::new(b"MSG");
    let g1pks: Vec<_> = pks.iter().map(|pk| pk.to_g1_publickey()).collect();
    assert_eq!(g1pks0, g1pks);
    agg.verify_by_pks(input,g1pks.iter()).unwrap();
}
