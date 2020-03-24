
use std::io;

use ff::{Field, PrimeField, PrimeFieldRepr}; // ScalarEngine
use zcash_primitives::jubjub::{
    JubjubEngine, FixedGenerators, JubjubParams,
    PrimeOrder, Unknown, edwards::Point
};

use crate::Params;

impl<E: JubjubEngine> Params<E> {
    pub(crate) fn scalar_to_point(&self, scalar: &Scalar<E>) -> Point<E,PrimeOrder> {
        // Jubjub generator point. TODO: prime or ---
        let base_point = self.engine.generator(FixedGenerators::SpendingKeyGenerator);
        base_point.mul(scalar.clone(), &self.engine)
    }
}

pub(crate) type Scalar<E: JubjubEngine> = E::Fs;

pub(crate) fn read_scalar<E: JubjubEngine, R: io::Read>(reader: R) -> io::Result<E::Fs> {
    let mut s_repr = <E::Fs as PrimeField>::Repr::default();
    s_repr.read_le(reader) ?;

    E::Fs::from_repr(s_repr)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "scalar is not in field"))
}

pub(crate) fn write_scalar<E: JubjubEngine, W: io::Write>(s: &E::Fs, writer: W) -> io::Result<()> {
    s.into_repr().write_le(writer)
}

