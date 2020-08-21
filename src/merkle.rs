// -*- mode: rust; -*-
//
// Copyright (c) 2019 Web 3 Foundation
//
// Authors:
// - Sergey Vasilyev <swasilyev@gmail.com>
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### Ring representation as Merkle tree 


use std::io;

use core::ops::{Deref, DerefMut};
use core::iter::IntoIterator;
use core::borrow::Borrow;

use ff::{PrimeField, Field};
use zcash_primitives::jubjub::JubjubEngine;
use crate::{JubjubEngineWithParams, PublicKey};
use neptune::{Poseidon, Arity};
use std::marker::PhantomData;


/// A point in the authentication path.
#[derive(Clone, Debug)]
pub(crate) struct CopathPoint<E: JubjubEngine, A: Arity<E::Fr>> { // TODO: PrimeField?
    /// The current selection. That is, the opposite of sibling.
    pub current_selection: Option<usize>,
    /// Sibling value, if it exists.
    pub siblings: Vec<Option<E::Fr>>,
    _a: PhantomData<A>,
}

impl<E: JubjubEngine, A: Arity<E::Fr>> CopathPoint<E, A> {
//    pub fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
//        let mut repr = <E::Fr as PrimeField>::Repr::default();
//        reader.read_exact(repr.as_mut()) ?;
//
//        use MerkleSelection::*;
//        let current_selection = if (repr.as_ref()[31] >> 7) == 1 { Left } else { Right };
//        repr.as_mut()[31] &= 0x7f;
//
//        let err = || io::Error::new(io::ErrorKind::InvalidInput, "auth path point is not in field" );
//
//        // zcash_primitives::jubjub::fs::MODULUS_BITS = 252
//        let sibling = if (repr.as_ref()[31] >> 6) != 1 {
//            repr.as_mut()[31] &= 0x3f;
//            Some(E::Fr::from_repr(repr).ok_or_else(err) ?)
//        } else { None };
//
//        Ok(CopathPoint { current_selection, siblings: vec![sibling], _a: Default::default() })
//    }
//
//    pub fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
//        let mut repr = self.siblings[0].map( |x| x.to_repr() ).unwrap_or_default();
//        assert!((repr.as_mut()[31] & 0xf0) == 0); // repr takes 252 bits so the highest 4 should be unset
//
//        if self.siblings[0].is_none() {
//            repr.as_mut()[31] |= 0x40;
//        }
//
//        if self.current_selection == MerkleSelection::Left {
//            repr.as_mut()[31] |= 0x80;
//        }
//
//        writer.write_all(repr.as_ref())
//    }

    pub fn random<R: rand_core::RngCore>(rng: &mut R) -> Self {
        let current_selection = Some((rng.next_u32() % A::to_u32()) as usize);
        let mut siblings = vec![];
        siblings.resize_with(A::to_usize() - 1, || Some(<E::Fr>::random(rng)));
        Self {
            current_selection,
            siblings,
            _a: Default::default()
        }
    }
}


/// Compute Merkle root and path
///
/// Leaves list argument unusable
fn merkleize<E>(
    depth: usize,
    mut list: &mut [E::Fr],
    mut index: usize,
    mut f: impl FnMut(CopathPoint<E, E::Arity>) -> (),
) -> E::Fr
where E: JubjubEngineWithParams,
{
    assert!( list.len() > 0 );
    // let mut tail = 0usize;
    // if list.len().count_ones() != 1 {
    //    let s = 0usize.leadng_zeros() - list.len().leading_zeros() - 1;
    //     tail = (1usize << s) - list.len();
    // }
    use typenum::marker_traits::Unsigned;
    let arity = E::Arity::to_usize();

    for depth_to_bottom in 0..depth {
        let chunk_index = index / arity;
        let index_within_chunk = index % arity;
        let chunk = list
            .chunks(arity)
            .nth(chunk_index)
            .expect("leaf index out of range");
        assert!(index_within_chunk < chunk.len()); // last chunk may not be exact
        let remainder_len = arity - chunk.len();
        let siblings: Vec<_> = chunk
            .into_iter()
            .enumerate()
            .filter(|(i, _)| *i != index_within_chunk)
            .map(|(_, x)| Some(x.clone()))
            .chain(std::iter::repeat(None).take(remainder_len)) // last chunk may not be exact
            .collect();
        assert!(siblings.len() == arity - 1); // element at index is excluded

        f(CopathPoint {
            current_selection: Some(index_within_chunk),
            siblings,
            _a: Default::default()
        });

        let list =  &mut list.chunks(arity).map(|chunk| {
            let remainder_len = arity - chunk.len();
            let chunk: Vec<_> = chunk.iter()
                .map(|x| Some(x.clone()))
                .chain(std::iter::repeat(None).take(remainder_len)) // last chunk may not be exact
                .collect();
            auth_hash::<E>(&chunk)
        }).collect::<Vec<_>>();

        index /= arity;
    }

    list[0].clone()
}

/// The authentication path of the merkle tree.
#[derive(Clone, Debug)]
pub struct RingSecretCopath<E: JubjubEngine, A: Arity<E::Fr>>(pub(crate) Vec<CopathPoint<E, A>>);

impl<E: JubjubEngineWithParams> RingSecretCopath<E, E::Arity> {
    /// Create a random path.
    pub fn random<R: rand_core::RngCore>(depth: u32, rng: &mut R) -> Self {
        use std::convert::TryInto;
        let mut path = vec![];
        path.resize_with(depth.try_into().unwrap(), || CopathPoint::random(rng));
        RingSecretCopath(path)
    }

    pub fn depth(&self) -> u32 {
        use core::convert::TryInto;
        self.0.len().try_into().unwrap()
    }

    /// Create a path from a given plain list, of target specified as `list_index`.
    /// Panic if `list_index` is out of bound.
    pub fn from_publickeys<B, I>(iter: I, index: usize, depth: usize) -> (Self, RingRoot<E>)
    where
        B: Borrow<PublicKey<E>>,
        I: IntoIterator<Item=B>
    {
        let mut list = iter.into_iter().map( |pk| pk.borrow().0.to_xy().0 ).collect::<Vec<_>>();
        let path_len = 0usize.leading_zeros() - depth.leading_zeros();
        let mut copath = Vec::with_capacity(path_len as usize);
        assert!(list.len() > 1);
        let root = merkleize( depth, list.as_mut_slice(), index, |x| copath.push(x) );
        (RingSecretCopath(copath), RingRoot(root))
    }

//    pub fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
//        let mut len = [0u8; 4];
//        reader.read_exact(&mut len) ?;
//        let len = u32::from_le_bytes(len) as usize;
//        let mut copath = Vec::with_capacity(len);
//        for _ in 0..len {
//            copath.push( CopathPoint::read(&mut reader) ? );
//        }
//        Ok(RingSecretCopath(copath))
//    }
//
//    pub fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
//        let len: u32 = self.depth();
//        writer.write_all(& len.to_le_bytes()) ?;
//        for app in self.0.iter() {
//            app.write(&mut writer) ?;
//        }
//        Ok(())
//    }

    /// Get the merkle root from proof.
    pub fn to_root(&self, leaf: &PublicKey<E>) -> RingRoot<E> {
        let mut cur = leaf.0.to_xy().0;

        for (depth_to_bottom, point) in self.0.iter().enumerate() {
            let mut chunk = point.siblings.clone();
            chunk.insert(point.current_selection.expect("element index in copath not specified"), Some(cur));
            cur = auth_hash::<E>(&chunk);
        }

        RingRoot(cur)
    }

}

/*
impl<E: JubjubEngine> Default for RingSecretCopath<E> {
    fn default() -> RingSecretCopath<E> {
        RingSecretCopath(Default::default())
    }
}
*/

/*
impl<E: JubjubEngine> Deref for RingSecretCopath<E> {
    type Target = Vec<CopathPoint<E>>;

    fn deref(&self) -> &Vec<CopathPoint<E>> {
        &self.0
    }
}

impl<E: JubjubEngine> DerefMut for RingSecretCopath<E> {
    fn deref_mut(&mut self) -> &mut Vec<CopathPoint<E>> {
        &mut self.0
    }
}
*/

/// The authentication root / merkle root of a given tree.
pub struct RingRoot<E: JubjubEngine>(pub E::Fr);

impl<E: JubjubEngine> Deref for RingRoot<E> {
    type Target = E::Fr;
    fn deref(&self) -> &E::Fr { &self.0 }
}

impl<E: JubjubEngine> DerefMut for RingRoot<E> {
    fn deref_mut(&mut self) -> &mut E::Fr { &mut self.0 }
}

impl<E: JubjubEngineWithParams> RingRoot<E> {
    /// Get the merkle root from a list of public keys. Panic if length of the list is zero.
    ///
    /// TODO: We do no initial hashing here for the leaves, but maybe that's fine.
    pub fn from_publickeys<B,I>(iter: I, depth: usize) -> Self
    where B: Borrow<PublicKey<E>>, I: IntoIterator<Item=B>
    {
        let mut list = iter.into_iter().map( |pk| pk.borrow().0.to_xy().0 ).collect::<Vec<_>>();
        assert!(list.len() > 1);
        RingRoot(merkleize( depth, list.as_mut_slice(), 0 , |_: CopathPoint<E, E::Arity>| () ))
    }

    pub fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let mut repr = <E::Fr as PrimeField>::Repr::default();
        reader.read_exact(repr.as_mut()) ?;
        let err = || io::Error::new(io::ErrorKind::InvalidInput, "auth path point is not in field" );
        Ok(RingRoot( E::Fr::from_repr(repr).ok_or_else(err) ? ))
    }

    pub fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(self.0.to_repr().as_ref())
    }
}

/// Hash function used to create the authenticated Merkle tree.
pub fn auth_hash<E: JubjubEngineWithParams>(chunk: &[Option<E::Fr>]) -> E::Fr {
    let zero = <E::Fr>::zero();
    let chunk: Vec<_> = chunk.iter().map(|o| o.unwrap_or(zero)).collect();
    let mut p = Poseidon::new_with_preimage(&chunk, E::poseidon_params());
    p.hash()
}



//#[cfg(test)]
//mod tests {
//
//    use super::*;
//    use pairing::bls12_381::{Bls12, Fr};
//
//
//    impl PartialEq for CopathPoint<Bls12> {
//        fn eq(&self, other: &Self) -> bool {
//            self.current_selection == other.current_selection
//            && self.sibling == other.sibling
//        }
//    }
//
//    #[test]
//    fn test_serialization() {
//        let p = CopathPoint::<Bls12> {
//            current_selection: MerkleSelection::Left,
//            sibling: Some(Fr::from(123u64))
//        };
//
//        let mut v = vec![];
//        p.write(&mut v).unwrap();
//
//        assert_eq!(v.len(), 32);
//
//        let de_p: CopathPoint::<Bls12> = CopathPoint::read(&v[..]).unwrap();
//        assert_eq!(p, de_p);
//    }
//}
