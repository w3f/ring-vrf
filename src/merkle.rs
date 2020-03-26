
use std::io;

use core::ops::{Deref, DerefMut};
use core::iter::IntoIterator;
use core::borrow::Borrow;

use ff::{PrimeField, PrimeFieldRepr, BitIterator, Field}; // ScalarEngine
use pairing::bls12_381::Fr;
use zcash_primitives::jubjub::JubjubEngine;
use zcash_primitives::pedersen_hash;
use crate::{Params, PublicKey};


/// Direction of the binary merkle path, either going left or right.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MerkleSelection {
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
pub struct AuthPathPoint<E: JubjubEngine> {
    /// The current selection. That is, the opposite of sibling.
    pub current_selection: MerkleSelection,
    /// Sibling value, if it exists.
    pub sibling: Option<E::Fr>,
}

impl<E: JubjubEngine> AuthPathPoint<E> {
    pub fn read<R: io::Read>(reader: R, params: &E::Params) -> io::Result<Self> {
        let mut repr = <E::Fr as PrimeField>::Repr::default();
        repr.read_le(reader) ?;

        use MerkleSelection::*;
        let current_selection = if (repr.as_ref()[3] >> 63) == 1 { Left } else { Right };
        repr.as_mut()[3] &= 0x7fffffffffffffff;

        let err = |_| io::Error::new(io::ErrorKind::InvalidInput, "auth path point is not in field" );

        // zcash_primitives::jubjub::fs::MODULUS_BITS = 252
        let sibling = if (repr.as_ref()[3] >> 62) == 1 {
            repr.as_mut()[3] &= 0x3fffffffffffffff;
            Some(E::Fr::from_repr(repr).map_err(err) ?)
        } else { None };

        Ok(AuthPathPoint { current_selection, sibling })
    }

    pub fn write<W: io::Write>(&self, writer: W) -> io::Result<()> {
        let mut repr = self.sibling.map( |x| x.into_repr() ).unwrap_or_default();
        assert!((repr.as_mut()[3] & 0x7fffffffffffffff) == 0);

        if self.sibling.is_none() {
            repr.as_mut()[3] |= 0x4000000000000000u64;
        }

        if self.current_selection == MerkleSelection::Left {
            repr.as_mut()[3] |= 0x8000000000000000u64;
        }

        repr.write_le(writer)
    }
}

/// The authentication path of the merkle tree.
#[derive(Clone, Debug)]
pub struct AuthPath<E: JubjubEngine>(pub Vec<AuthPathPoint<E>>);

impl<E: JubjubEngine> AuthPath<E> {
    /// Create a random path.
    pub fn random<R: rand_core::RngCore>(depth: usize, rng: &mut R) -> Self {
        Self(vec![AuthPathPoint {
            current_selection: MerkleSelection::random(rng),
            sibling: Some(<E::Fr>::random(rng))
        }; depth])
    }

    /// Create a path from a given plain list, of target specified as `list_index`.
    /// Panic if `list_index` is out of bound.
    pub fn from_list(list: &[E::Fr], list_index: usize, params: &Params<E>) -> Self {
        let mut depth_to_bottom = 0;
        let mut tracked_index = list_index;
        let mut cur = list.iter().cloned().collect::<Vec<_>>();
        let mut path = <AuthPath<E>>::default();

        while cur.len() > 1 {
            let mut next = Vec::new();

            let left = cur.pop();
            let right = cur.pop();

            next.push(auth_hash::<E>(left.as_ref(), right.as_ref(), depth_to_bottom, params));

            let (current_selection, sibling_index) = if tracked_index % 2 == 0 {
                (MerkleSelection::Left, tracked_index + 1)
            } else {
                (MerkleSelection::Right, tracked_index - 1)
            };
            path.push(AuthPathPoint {
                current_selection,
                sibling: next.get(sibling_index).cloned()
            });

            cur = next;
            depth_to_bottom += 1;
            tracked_index /= 2;
        }

        path
    }

    /*
    TODO:
    pub fn read<R: io::Read>(reader: R, params: &E::Params) -> io::Result<Self> {
    }

    pub fn write<W: io::Write>(&self, writer: W) -> io::Result<()> {
    }
    */
}

impl<E: JubjubEngine> Default for AuthPath<E> {
    fn default() -> Self {
        Self(Default::default())
    }
}

impl<E: JubjubEngine> Deref for AuthPath<E> {
    type Target = Vec<AuthPathPoint<E>>;

    fn deref(&self) -> &Vec<AuthPathPoint<E>> {
        &self.0
    }
}

impl<E: JubjubEngine> DerefMut for AuthPath<E> {
    fn deref_mut(&mut self) -> &mut Vec<AuthPathPoint<E>> {
        &mut self.0
    }
}

/// The authentication root / merkle root of a given tree.
pub struct AuthRoot<E: JubjubEngine>(pub E::Fr);

impl<E: JubjubEngine> Deref for AuthRoot<E> {
    type Target = E::Fr;
    fn deref(&self) -> &E::Fr { &self.0 }
}

impl<E: JubjubEngine> DerefMut for AuthRoot<E> {
    fn deref_mut(&mut self) -> &mut E::Fr { &mut self.0 }
}

impl<E: JubjubEngine> AuthRoot<E> {
    /// Get the merkle root from proof.
    pub fn from_proof(path: &AuthPath<E>, target: &PublicKey<E>, params: &Params<E>) -> Self {
        let mut cur = target.0.to_xy().0;

        for (depth_to_bottom, point) in path.iter().enumerate() {
            let (left, right) = match point.current_selection {
                MerkleSelection::Right => (point.sibling.as_ref(), Some(&cur)),
                MerkleSelection::Left => (Some(&cur), point.sibling.as_ref()),
            };

            cur = auth_hash::<E>(left, right, depth_to_bottom, params);
        }

        Self(cur)
    }

    /// Get the merkle root from a plain list. Panic if length of the list is zero.
    ///
    /// TODO: Should this be public?
    fn from_list<I>(iter: I, params: &Params<E>) -> Self
    where I: IntoIterator<Item=E::Fr>
    // where I: IntoIterator<Item=impl Borrow<E::Fr>>
    {
        let mut depth_to_bottom = 0;
        let mut cur = iter.into_iter().collect::<Vec<_>>();
        let mut next = Vec::new();

        while cur.len() > 1 {
            let left = cur.pop();
            let right = cur.pop();

            next.push(auth_hash::<E>(left.as_ref(), right.as_ref(), depth_to_bottom, params));

            ::core::mem::swap(&mut cur,&mut next);
            next.clear();
            depth_to_bottom += 1;
        }

        Self(cur.pop().expect("initial list is not empty; qed"))
    }

    /// Get the merkle root from a list of public keys. Panic if length of the list is zero.
    ///
    /// TODO: We do no initial hashing here for the leaves, but maybe that's fine.
    pub fn from_publickeys<B,I>(iter: I, params: &Params<E>) -> Self
    where B: Borrow<PublicKey<E>>, I: IntoIterator<Item=B>
    {
        let iter = iter.into_iter().map( |pk| pk.borrow().0.to_xy().0 );
        Self::from_list(iter, params)
    }

    pub fn read<R: io::Read>(reader: R, params: &E::Params) -> io::Result<Self> {
        let mut repr = <E::Fr as PrimeField>::Repr::default();
        repr.read_le(reader) ?;
        let err = |_| io::Error::new(io::ErrorKind::InvalidInput, "auth path point is not in field" );
        Ok(AuthRoot( E::Fr::from_repr(repr).map_err(err) ? ))
    }

    pub fn write<W: io::Write>(&self, writer: W) -> io::Result<()> {
        self.0.into_repr().write_le(writer)
    }
}

/// Hash function used to create the authentication merkle tree.
pub fn auth_hash<E: JubjubEngine>(
    left: Option<&E::Fr>,
    right: Option<&E::Fr>,
    depth_to_bottom: usize,
    params: &Params<E>,
) -> E::Fr {
    let zero = <E::Fr>::zero();

    let mut lhs = BitIterator::new(left.unwrap_or(&zero).into_repr()).collect::<Vec<bool>>();
    let mut rhs = BitIterator::new(right.unwrap_or(&zero).into_repr()).collect::<Vec<bool>>();

    lhs.reverse();
    rhs.reverse();

    pedersen_hash::pedersen_hash::<E, _>(
        pedersen_hash::Personalization::MerkleTree(depth_to_bottom),
        lhs.into_iter()
            .take(Fr::NUM_BITS as usize)
            .chain(rhs.into_iter().take(Fr::NUM_BITS as usize)),
        &params.engine,
    ).to_xy().0
}

