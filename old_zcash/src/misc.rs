
use std::io;
use std::ops::Mul;

use ff::PrimeField;


// TODO: Avoid std::io entirely after switching to ZEXE
#[derive(Debug)]
pub enum SignatureError {
    VRFProofInvalid,
    IO(io::Error),
    Synthesis(bellman::SynthesisError),
}
impl From<io::Error> for SignatureError {
    fn from(err: io::Error) -> SignatureError {
        SignatureError::IO(err)
    }
}
impl From<bellman::SynthesisError> for SignatureError {
    fn from(err: bellman::SynthesisError) -> SignatureError {
        SignatureError::Synthesis(err)
    }
}
impl SignatureError {
    pub fn is_invalid_proof(&self) -> bool {
        match self {
            SignatureError::VRFProofInvalid => true,
            _ => false,
        }
    }
}

pub type SignatureResult<T> = Result<T,SignatureError>;

// impl<T> SignatureResult<T> {
//     pub fn is_valid_signature(&self) -> bool { self.is_ok() }
// }


// pub fn signature_error(msg: &'static str) -> SignatureError {
//     io::Error::new(io::ErrorKind::InvalidInput, msg)
// }



/// Serialization
///
/// ZCash types require `std` for all (de)serialization, which sucks but hey.
pub trait ReadWrite : Sized {
    fn read<R: io::Read>(reader: R) -> io::Result<Self>;
    fn write<W: io::Write>(&self, writer: W) -> io::Result<()>;
}

impl ReadWrite for () {
    fn read<R: io::Read>(_reader: R) -> io::Result<Self> { Ok(()) }
    fn write<W: io::Write>(&self, _writer: W) -> io::Result<()> { Ok(()) }
}


pub(crate) type Scalar = jubjub::Fr;

pub fn read_scalar<R: io::Read>(mut reader: R) -> io::Result<jubjub::Scalar> {
    let mut s_repr = <jubjub::Scalar as PrimeField>::Repr::default();
    reader.read_exact(s_repr.as_mut()) ?;

    jubjub::Scalar::from_repr(s_repr)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "scalar is not in field"))
}

pub fn write_scalar<W: io::Write>(s: &jubjub::Scalar, mut writer: W) -> io::Result<()> {
    writer.write_all(s.to_repr().as_ref())
}


/// Create a 128 bit `Scalar` for delinearization
pub(crate) fn scalar_from_u128(s: [u8; 16]) -> jubjub::Scalar
{
    let mut repr = <jubjub::Scalar as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(&s);
    jubjub::Scalar::from_repr(repr).unwrap()
}


pub(crate) fn scalar_times_generator(scalar: &jubjub::Scalar) -> jubjub::SubgroupPoint
{
    let base_point = zcash_primitives::constants::SPENDING_KEY_GENERATOR;
    base_point.mul(scalar.clone())
}

pub(crate) fn scalar_times_blinding_generator(scalar: &jubjub::Scalar) -> jubjub::SubgroupPoint
{
    let base_point = zcash_primitives::constants::NULLIFIER_POSITION_GENERATOR;
    base_point.mul(scalar.clone())
}


/*
pub fn hash_to_scalar<E: JubjubEngine>(ctx: &[u8], a: &[u8], b: &[u8]) -> E::Fs {
    let mut hasher = Params::new().hash_length(64).personal(ctx).to_state();
    hasher.update(a);
    hasher.update(b);
    let ret = hasher.finalize();
    E::Fs::to_uniform(ret.as_ref())
}
*/


/*
pub(crate) fn scalar_to_bytes<E: JubjubEngine>(s: &E::Fs)
 -> io::Result<[u8; ::core::mem::size_of::<<<E as JubjubEngine>::Fs as PrimeField>::Repr>()]> 
{
    let mut bytes = [0u8; ::core::mem::size_of::<<<E as JubjubEngine>::Fs as PrimeField>::Repr>()];
    write_scalar(s, &mut bytes[..]) ?;
    Ok(bytes)
}
*/

