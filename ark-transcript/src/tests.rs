use crate::{*, debug::TestVectorFakeRng};

#[test]
fn transcript_v_witnesses() {
    use ark_ed25519::Fr;

    // Check that the TranscriptRng is bound to the transcript and
    // the witnesses.  This is done by producing a sequence of
    // transcripts that diverge at different points and checking
    // that they produce different challenges.

    let protocol_label = b"test collisions";
    let commitment1 = b"commitment data 1";
    let commitment2 = b"commitment data 2";
    let witness1 = b"witness data 1";
    let witness2 = b"witness data 2";

    let mut t1 = Transcript::new_labeled(protocol_label);
    let mut t2 = Transcript::new_labeled(protocol_label);
    let mut t3 = Transcript::new_labeled(protocol_label);
    let mut t4 = Transcript::new_labeled(protocol_label);

    t1.write_bytes(commitment1);
    t2.write_bytes(commitment2);
    t3.write_bytes(commitment2);
    t4.write_bytes(commitment2);

    let mut r1 = t1.fork(b"witness").chain(witness1).witness(&mut TestVectorFakeRng);
    let mut r2 = t2.fork(b"witness").chain(witness1).witness(&mut TestVectorFakeRng);
    let mut r3 = t3.fork(b"witness").chain(witness2).witness(&mut TestVectorFakeRng);
    let mut r4 = t4.fork(b"witness").chain(witness2).witness(&mut TestVectorFakeRng);

    let s1: Fr = r1.read_uniform();
    let s2: Fr = r2.read_uniform();
    let s3: Fr = r3.read_uniform();
    let s4: Fr = r4.read_uniform();

    // Transcript t1 has different commitments than t2, t3, t4, so
    // it should produce distinct challenges from all of them.
    assert_ne!(s1, s2);
    assert_ne!(s1, s3);
    assert_ne!(s1, s4);

    // Transcript t2 has different witness variables from t3, t4,
    // so it should produce distinct challenges from all of them.
    assert_ne!(s2, s3);
    assert_ne!(s2, s4);

    // Transcripts t3 and t4 have the same commitments and
    // witnesses, so they should give different challenges only
    // based on the RNG. Checking that they're equal in the
    // presence of a bad RNG checks that the different challenges
    // above aren't because the RNG is accidentally different.
    assert_eq!(s3, s4);

    let s1: Fr = r1.read_reduce();
    let s2: Fr = r2.read_reduce();
    let s3: Fr = r3.read_reduce();
    let s4: Fr = r4.read_reduce();

    // Transcript t1 has different commitments than t2, t3, t4, so
    // it should produce distinct challenges from all of them.
    assert_ne!(s1, s2);
    assert_ne!(s1, s3);
    assert_ne!(s1, s4);

    // Transcript t2 has different witness variables from t3, t4,
    // so it should produce distinct challenges from all of them.
    assert_ne!(s2, s3);
    assert_ne!(s2, s4);

    // Transcripts t3 and t4 have the same commitments and
    // witnesses, so they should give different challenges only
    // based on the RNG. Checking that they're equal in the
    // presence of a bad RNG checks that the different challenges
    // above aren't because the RNG is accidentally different.
    assert_eq!(s3, s4);

}


#[test]
fn accumulation() {
    let protocol_label = b"test collisions";

    let mut t1 = Transcript::new_labeled(protocol_label);
    let mut t2 = Transcript::new_blank_accumulator();
    t2.label(protocol_label);

    let commitment1 = b"commitment data 1";
    let commitment2 = b"commitment data 2";

    t1.write_bytes(commitment1);
    t2.write_bytes(commitment1);

    t1.seperate();
    let v = t2.accumulator_finalize();
    let mut t3 = Transcript::from_accumulation(v);

    t1.write_bytes(commitment2);
    t3.write_bytes(commitment2);

    let c1: [u8; 32] = t1.challenge(b"challenge").read_byte_array();
    let c2: [u8; 32] = t3.challenge(b"challenge").read_byte_array();
    assert_eq!(c1,c2);
}

#[test]
fn challenge_in_accumulation() {
    let mut t1 = Transcript::new_blank_accumulator();
    let mut t2 = Transcript::new_blank_accumulator();

    let commitment1 = b"commitment data 1";
    let commitment2 = b"commitment data 2";

    t1.write_bytes(commitment1);
    t2.write_bytes(commitment1);

    t1.write_bytes(commitment2);
    t2.write_bytes(commitment2);

    let acc = t2.accumulator_finalize();
    let mut t3 = Transcript::from_accumulation(acc);

    let c1: [u8; 32] = t1.challenge(b"challenge").read_byte_array();
    let c2: [u8; 32] = t3.challenge(b"challenge").read_byte_array();

    assert_eq!(c1, c2);
}
