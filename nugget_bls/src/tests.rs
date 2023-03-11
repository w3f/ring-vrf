
use merlin::Transcript;

use ark_serialize::{CanonicalSerialize,CanonicalDeserialize};
use ark_std::vec::Vec;

// use crate::{SecretKey, PublicKey, Signature,};

type P = ark_bls12_381::Bls12_381;
type SecretKey = crate::SecretKey<P>;
type PublicKey = crate::PublicKey<P>;
type Signature = crate::Signature<P>;



#[test]
fn master() {
    let mut rng = &mut rand_core::OsRng;
    let sk = SecretKey::ephemeral();

    let mut buf = Vec::new();
    let pk0 = sk.create_nugget_public();
    pk0.serialize_compressed(&mut buf).unwrap();
    let pk = PublicKey::deserialize_compressed(buf.as_ref()).unwrap();
    assert_eq!(pk0,pk);
    pk.validate_nugget_public().unwrap();

    let t = Transcript::new(b"AD1");
    let msg = &mut Transcript::new(b"MSG1");
    let signature = sk.sign_nugget_bls(t,msg);
 
    buf.clear();
    signature.serialize_compressed(&mut buf).unwrap();
    let signature = Signature::deserialize_compressed(buf.as_ref()).unwrap();

    let t = Transcript::new(b"AD1");
    let msg = &mut Transcript::new(b"MSG1");
    pk.verify_nugget_bls(t,msg,&signature).unwrap();
}

