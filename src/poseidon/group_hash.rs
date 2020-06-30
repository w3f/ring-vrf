use blake2_rfc::blake2s::Blake2s;
use super::constants;

pub trait GroupHasher {
    fn new(personalization: &[u8]) -> Self;
    fn update(&mut self, data: &[u8]);
    fn finalize(&mut self) -> Vec<u8>;
}

pub struct BlakeHasher {
    h: Blake2s
}

impl GroupHasher for BlakeHasher {
    fn new(personalization: &[u8]) -> Self {
        let h = Blake2s::with_params(32, &[], &[], personalization);

        Self {
            h: h
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.h.update(data);
    }

    fn finalize(&mut self) -> Vec<u8> {
        use std::mem;

        let new_h = Blake2s::with_params(32, &[], &[], &[]);
        let h = std::mem::replace(&mut self.h, new_h);

        let result = h.finalize();

        result.as_ref().to_vec().clone()
    }
}

#[test]
fn blake2s_consistency_test() {
    let personalization = b"Hello_w!";
    let tag = b"World_123!";
    let mut h = Blake2s::with_params(32, &[], &[], personalization);
    h.update(constants::GH_FIRST_BLOCK);
    h.update(tag);
    let h = h.finalize().as_ref().to_vec();
    let reference = hex!("989e1d96f8d977db95b7fcb59d26fe7f66b4e21e84cdb9387b67aa78ebd07ecf");

    assert_eq!(reference[..], h[..]);
}