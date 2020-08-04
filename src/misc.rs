
use std::io;

use ff::PrimeField;
use zcash_primitives::jubjub::{
    JubjubEngine, FixedGenerators, JubjubParams,
    PrimeOrder, edwards::Point
};

use crate::JubjubEngineWithParams;


// TODO: Avoid std::io entirely after switching to ZEXE
pub type SignatureError = io::Error;
pub type SignatureResult<T> = io::Result<T>;

pub fn signature_error(msg: &'static str) -> SignatureError {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}



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


pub(crate) type Scalar<E> = <E as JubjubEngine>::Fs;

pub fn read_scalar<E: JubjubEngine, R: io::Read>(mut reader: R) -> io::Result<E::Fs> {
    let mut s_repr = <E::Fs as PrimeField>::Repr::default();
    reader.read_exact(s_repr.as_mut()) ?;

    E::Fs::from_repr(s_repr)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "scalar is not in field"))
}

pub fn write_scalar<E: JubjubEngine, W: io::Write>(s: &E::Fs, mut writer: W) -> io::Result<()> {
    writer.write_all(s.to_repr().as_ref())
}


/// Create a 128 bit `Scalar` for delinearization
pub(crate) fn scalar_from_u128<E>(s: [u8; 16]) -> Scalar<E> 
where E: JubjubEngine
{
    let mut repr = <Scalar<E> as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(&s);
    Scalar::<E>::from_repr(repr).unwrap()
}


pub(crate) fn scalar_times_generator<E>(scalar: &Scalar<E>)
 -> Point<E,PrimeOrder> 
where E: JubjubEngineWithParams,
{
    let params = E::params();
    let base_point = params.generator(FixedGenerators::SpendingKeyGenerator);
    base_point.mul(scalar.clone(), params)
}

pub(crate) fn scalar_times_blinding_generator<E>(scalar: &Scalar<E>)
 -> Point<E,PrimeOrder> 
where E: JubjubEngineWithParams,
{
    let params = E::params();
    let base_point = params.generator(FixedGenerators::NullifierPosition);
    base_point.mul(scalar.clone(), params)
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

