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
use group::Curve;
use jubjub::ExtendedPoint;
use bls12_381::Scalar as Fr;
use zcash_primitives::pedersen_hash;
use crate::PublicKey;


/// Direction of the binary Merkle path, either going left or right.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum MerkleSelection {
    /// Move left to the sub-node.
    Left,
    /// Move right to the sub-node.
    Right,
}

impl MerkleSelection {
    /// Create a random path direction from a random source.
    pub fn random<R: rand_core::RngCore>(rng: &mut R) -> Self {
        if rng.next_u32() % 2 == 0 {
            MerkleSelection::Left
        } else {
            MerkleSelection::Right
        }
    }
}


/// A point in the authentication path.
#[derive(Clone, Debug)]
pub(crate) struct CopathPoint {
    /// The current selection. That is, the opposite of sibling.
    pub current_selection: MerkleSelection,
    /// Sibling value, if it exists.
    pub sibling: Option<jubjub::Fq>,
}

impl CopathPoint {
    pub fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let mut repr = <bls12_381::Scalar as PrimeField>::Repr::default();
        reader.read_exact(repr.as_mut()) ?;

        use MerkleSelection::*;
        let current_selection = if (repr.as_ref()[31] >> 7) == 1 { Left } else { Right };
        repr.as_mut()[31] &= 0x7f;

        let err = || io::Error::new(io::ErrorKind::InvalidInput, "auth path point is not in field" );

        // zcash_primitives::jubjub::fs::MODULUS_BITS = 252
        let sibling = if (repr.as_ref()[31] >> 6) != 1 {
            repr.as_mut()[31] &= 0x3f;
            Some(bls12_381::Scalar::from_repr(repr).ok_or_else(err) ?)
        } else { None };

        Ok(CopathPoint { current_selection, sibling })
    }

    pub fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        let mut repr = self.sibling.map( |x| x.to_repr() ).unwrap_or_default();
        assert!((repr.as_mut()[31] & 0xf0) == 0); // repr takes 252 bits so the highest 4 should be unset

        if self.sibling.is_none() {
            repr.as_mut()[31] |= 0x40;
        }

        if self.current_selection == MerkleSelection::Left {
            repr.as_mut()[31] |= 0x80;
        }

        writer.write_all(repr.as_ref())
    }
}


/// Compute Merkle root and path
///
/// Leaves list argument unusable
fn merkleize(
    depth: usize,
    mut list: &mut [jubjub::Fq],
    mut index: usize,
    mut f: impl FnMut(CopathPoint) -> (),
) -> jubjub::Fq
{
    assert!( list.len() > 0 );
    // let mut tail = 0usize;
    // if list.len().count_ones() != 1 {
    //    let s = 0usize.leadng_zeros() - list.len().leading_zeros() - 1;
    //     tail = (1usize << s) - list.len();
    // }

    for depth_to_bottom in 0..depth {
        let (current_selection, sibling) = if index % 2 == 0 {
            (MerkleSelection::Left, list.get(index).cloned())
        } else {
            (MerkleSelection::Right, list.get(index).cloned())
        };
        f(CopathPoint { current_selection, sibling, });

        for i in (0..list.len()).filter(|x| x % 2 == 0) { 
            let left = list.get(i);
            let right = list.get(i+1);
            list[i/2] = auth_hash(left, right, depth_to_bottom);
        }

        index /= 2;

        let len = list.len() + (list.len() % 2);
        list = &mut list[0..len/2]
    }

    list[0].clone()
}

/// The authentication path of the merkle tree.
#[derive(Clone, Debug)]
pub struct RingSecretCopath(pub(crate) Vec<CopathPoint>);

impl RingSecretCopath {
    /// Create a random path.
    pub fn random<R: rand_core::RngCore>(depth: u32, rng: &mut R) -> Self {
        RingSecretCopath(vec![CopathPoint {
            current_selection: MerkleSelection::random(rng),
            sibling: Some(bls12_381::Scalar::random(rng))
        }; depth as usize])
    }

    pub fn depth(&self) -> u32 {
        use core::convert::TryInto;
        self.0.len().try_into().unwrap()
    }

    /// Create a path from a given plain list, of target specified as `list_index`.
    /// Panic if `list_index` is out of bound.
    pub fn from_publickeys<B,I>(iter: I, index: usize, depth: usize) -> (Self, RingRoot)
    where B: Borrow<PublicKey>, I: IntoIterator<Item=B>
    {
        let mut list = iter.into_iter().map( |pk| pk.borrow().0.to_affine().get_u() ).collect::<Vec<_>>();
        let path_len = 0usize.leading_zeros() - depth.leading_zeros();
        let mut copath = Vec::with_capacity(path_len as usize);
        assert!(list.len() > 1);
        let root = merkleize( depth, list.as_mut_slice(), index, |x| copath.push(x) );
        (RingSecretCopath(copath), RingRoot(root))
    }

    pub fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let mut len = [0u8; 4];
        reader.read_exact(&mut len) ?;
        let len = u32::from_le_bytes(len) as usize;
        let mut copath = Vec::with_capacity(len);
        for _ in 0..len {
            copath.push( CopathPoint::read(&mut reader) ? );
        }
        Ok(RingSecretCopath(copath))
    }

    pub fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        let len: u32 = self.depth();
        writer.write_all(& len.to_le_bytes()) ?;
        for app in self.0.iter() {
            app.write(&mut writer) ?;
        }
        Ok(())
    }

    /// Get the merkle root from proof.
    pub fn to_root(&self, leaf: &PublicKey) -> RingRoot {
        let mut cur = leaf.0.to_affine().get_u();

        for (depth_to_bottom, point) in self.0.iter().enumerate() {
            let (left, right) = match point.current_selection {
                MerkleSelection::Right => (point.sibling.as_ref(), Some(&cur)),
                MerkleSelection::Left => (Some(&cur), point.sibling.as_ref()),
            };

            cur = auth_hash(left, right, depth_to_bottom);
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
pub struct RingRoot(pub jubjub::Fq);

impl Deref for RingRoot {
    type Target = jubjub::Fq;
    fn deref(&self) -> &jubjub::Fq { &self.0 }
}

impl DerefMut for RingRoot {
    fn deref_mut(&mut self) -> &mut jubjub::Fq { &mut self.0 }
}

impl RingRoot {
    /// Get the merkle root from a list of public keys. Panic if length of the list is zero.
    ///
    /// TODO: We do no initial hashing here for the leaves, but maybe that's fine.
    pub fn from_publickeys<B,I>(iter: I, depth: usize) -> Self
    where B: Borrow<PublicKey>, I: IntoIterator<Item=B>
    {
        let mut list = iter.into_iter().map( |pk| pk.borrow().0.to_affine().get_u() ).collect::<Vec<_>>();
        assert!(list.len() > 1);
        RingRoot(merkleize( depth, list.as_mut_slice(), 0 , |_: CopathPoint| () ))
    }

    pub fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let mut repr = <bls12_381::Scalar as PrimeField>::Repr::default();
        reader.read_exact(repr.as_mut()) ?;
        let err = || io::Error::new(io::ErrorKind::InvalidInput, "auth path point is not in field" );
        Ok(RingRoot( bls12_381::Scalar::from_repr(repr).ok_or_else(err) ? ))
    }

    pub fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(self.0.to_repr().as_ref())
    }
}

/// Hash function used to create the authenticated Merkle tree.
pub fn auth_hash(
    left: Option<&jubjub::Fq>,
    right: Option<&jubjub::Fq>,
    depth_to_bottom: usize,
) -> jubjub::Fq {
    let zero = jubjub::Fq::zero();

    let lhs = left.unwrap_or(&zero).to_le_bits();
    let rhs = right.unwrap_or(&zero).to_le_bits();

    ExtendedPoint::from(pedersen_hash::pedersen_hash(
        pedersen_hash::Personalization::MerkleTree(depth_to_bottom),
        lhs.into_iter()
            .take(Fr::NUM_BITS as usize)
            .chain(rhs.into_iter().take(Fr::NUM_BITS as usize))
            .cloned()
    )).to_affine().get_u()
}



#[cfg(test)]
mod tests {

    use super::*;

    impl PartialEq for CopathPoint {
        fn eq(&self, other: &Self) -> bool {
            self.current_selection == other.current_selection
            && self.sibling == other.sibling
        }
    }

    #[test]
    fn test_serialization() {
        let p = CopathPoint {
            current_selection: MerkleSelection::Left,
            sibling: Some(Fr::from(123u64))
        };

        let mut v = vec![];
        p.write(&mut v).unwrap();

        assert_eq!(v.len(), 32);

        let de_p: CopathPoint = CopathPoint::read(&v[..]).unwrap();
        assert_eq!(p, de_p);
    }
}
