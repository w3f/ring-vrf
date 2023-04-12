
use crate::{RngCore,CryptoRng};

/// We need a constant `RngCore` for providing test vectors, both
/// for ourselves and others usage.
pub struct TestVectorFakeRng;

impl RngCore for TestVectorFakeRng {
    fn next_u32(&mut self) -> u32 {  0  }
    fn next_u64(&mut self) -> u64 {  0  }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for i in dest.iter_mut() {  *i = 0;  }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), ::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for TestVectorFakeRng {}

