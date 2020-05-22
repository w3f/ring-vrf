
use std::io;

use ff::{PrimeField, PrimeFieldRepr}; // Field, ScalarEngine
use zcash_primitives::jubjub::{
    JubjubEngine, FixedGenerators, JubjubParams,
    PrimeOrder, edwards::Point, // Unknown, ToUniform,
};

use crate::JubjubEngineWithParams;


/// Create a 128 bit `Scalar` for delinearization
///
/// TODO: Improve this
pub(crate) fn scalar_from_u128<E>(s: [u8; 16]) -> Scalar<E> 
where E: JubjubEngine
{
    let (x,y) = array_refs!(&s,8,8);
    let mut x: <E::Fs as PrimeField>::Repr = u64::from_le_bytes(*x).into();
    let y: <E::Fs as PrimeField>::Repr = u64::from_le_bytes(*y).into();
    x.shl(64);
    x.add_nocarry(&y);
    <E::Fs as PrimeField>::from_repr(x).unwrap()
    // Scalar::from(u128::from_le_bytes(s))  ?dalek?
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

pub(crate) type Scalar<E> = <E as JubjubEngine>::Fs;

pub(crate) fn read_scalar<E: JubjubEngine, R: io::Read>(reader: R) -> io::Result<E::Fs> {
    let mut s_repr = <E::Fs as PrimeField>::Repr::default();
    s_repr.read_le(reader) ?;

    E::Fs::from_repr(s_repr)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "scalar is not in field"))
}

pub(crate) fn write_scalar<E: JubjubEngine, W: io::Write>(s: &E::Fs, writer: W) -> io::Result<()> {
    s.into_repr().write_le(writer)
}

/*
pub(crate) fn scalar_to_bytes<E: JubjubEngine>(s: &E::Fs)
 -> io::Result<[u8; ::core::mem::size_of::<<<E as JubjubEngine>::Fs as PrimeField>::Repr>()]> 
{
    let mut bytes = [0u8; ::core::mem::size_of::<<<E as JubjubEngine>::Fs as PrimeField>::Repr>()];
    write_scalar(s, &mut bytes[..]) ?;
    Ok(bytes)
}
*/

