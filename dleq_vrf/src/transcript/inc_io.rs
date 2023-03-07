
/// Arkworks Reader & Writer for Merlin Transcripts
///
/// We produce challenges in Chaum-Pederson DLEQ proofs using transcripts,
/// for which [merlin](https://merlin.cool/) provides a convenient tool.
/// Arkworks de/serializes conveniently but with compile-time length
/// information existing only locally, via its `io::{Read,Write}` traits.
/// `TranscriptIO` attaches the `label` required by merlin.
///
#[derive(Clone)]
pub struct TranscriptIO<T> {
    pub label: &'static [u8],
    pub t: T,
}

/// Read bytes from the transcript
impl<T> RngCore for TranscriptIO<T> where TranscriptIO<T>: Read {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.read(&mut b).expect("Infalable, qed");
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.read(&mut b).expect("Infalable, qed");
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.read(dest).expect("Infalable, qed");
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// impl<T: BorrowMut<Transcript>> CryptoRng for TranscriptIO<T> { }


