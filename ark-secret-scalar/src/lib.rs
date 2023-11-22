// Copyright (c) 2019-2020 Web 3 Foundation

#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]

use core::{
    cell::UnsafeCell,
    ops::{Add,AddAssign,Mul}
};

use ark_ff::{PrimeField}; // Field, Zero
use ark_ec::{AffineRepr, Group}; // CurveGroup

use digest::{XofReader};
pub use getrandom_or_panic::{RngCore,CryptoRng,rand_core,getrandom_or_panic};
// use subtle::{Choice,ConstantTimeEq};
use zeroize::Zeroize;

// TODO:  Remove ark-transcript dependency once https://github.com/arkworks-rs/algebra/pull/643 lands
use ark_transcript::xof_read_reduced;



pub struct Rng2Xof<R: RngCore+CryptoRng>(pub R);
impl<R: RngCore+CryptoRng> XofReader for Rng2Xof<R> {
    fn read(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }
}


/// Secret scalar split into the sum of two scalars, which randomly
/// mutate but retain the same sum.   Incurs 2x penalty in scalar
/// multiplications, but provides side channel defenses.
/// 
/// We support `&self` recievers throughout, just like typical secret keys,
/// but doing so demands interior mutability.  We choose a non-thread-safe
/// implementation which avoids atomics, meaning `Send` but `!Sync`.
/// As `Mutex<T: Send>: Send+Sync`, one should prefer `Mutex<SecretKey>`
/// over cloning `SecretScalar`, simply to minimize clones of secret keys.
/// 
/// In this, we employ `UnsafeCell` directly but avoid rentrancy completely,
/// meaning we never provide direct access to the individual scalars, only
/// their sum.  `Cell` would've copied of secret keys too much.  `RefCell`
/// would be secure here, but appears unecessary and `#[repr(transparent)]`
/// maybe gives advantages.
/// 
// TODO:  We split additively right now, but would a multiplicative splitting
// help against rowhammer attacks on the secret key?
#[repr(transparent)]
pub struct SecretScalar<F: PrimeField>(UnsafeCell<[F; 2]>);

impl<F: PrimeField> Clone for SecretScalar<F> {
    fn clone(&self) -> SecretScalar<F> {
        let n = self.operate(|ss| ss.clone());
        self.resplit();
        SecretScalar(UnsafeCell::new(n) )
    }
}

impl<F: PrimeField> PartialEq for SecretScalar<F> {
    fn eq(&self, rhs: &SecretScalar<F>) -> bool {
        let lhs = unsafe { &*self.0.get() };
        let rhs = unsafe { &*rhs.0.get() };
        ( (lhs[0] - rhs[0]) + (lhs[1] - rhs[1]) ).is_zero()
    }
}
impl<F: PrimeField> Eq for SecretScalar<F> {}

impl<F: PrimeField> Zeroize for SecretScalar<F> { 
    fn zeroize(&mut self) {
        self.0.get_mut().zeroize()
    }
}
impl<F: PrimeField> Drop for SecretScalar<F> {
    fn drop(&mut self) { self.zeroize() }
}

impl<F: PrimeField> SecretScalar<F> {
    /// Do computations with an immutable borrow of the two scalars.
    ///
    /// At the module level, we keep this method private, never pass
    /// these references into user's code, and never accept user's
    /// closures, so our being `!Sync` ensures memory safety.
    /// All other method ensure only the sum of the scalars is visible
    /// outside this module too.
    fn operate<R,O>(&self, f : O) -> R
    where O: FnOnce(&[F; 2]) -> R
    {
        f(unsafe { &*self.0.get() })
    }

    /// Internal clone which skips replit.
    fn risky_clone(&self) -> SecretScalar<F> {
        let n = self.operate(|ss| ss.clone());
        SecretScalar(UnsafeCell::new(n) )
    }

    /// Immutably borrow `&self` but add opposite random values to its two scalars.
    /// 
    /// We encapsulate exposed interior mutability of `SecretScalar` here, but
    /// our other methods should never reveal references into the scalars,
    /// or even their individual valus.
    pub fn resplit(&self) {
        let mut xof = Rng2Xof(getrandom_or_panic());
        let x = xof_read_reduced(&mut xof);
        let selfy = unsafe { &mut *self.0.get() };
        selfy[0] += &x;
        selfy[1] -= &x;
    }

    pub fn resplit_mut(&mut self) {
        let mut xof = Rng2Xof(getrandom_or_panic());
        let x = xof_read_reduced(&mut xof);
        let selfy = self.0.get_mut();
        selfy[0] += &x;
        selfy[1] -= &x;
    }

    /// Initialize and unbiased `SecretScalar` from a `XofReaader`.
    pub fn from_xof<R: XofReader>(xof: &mut R) -> Self {
        let mut xof = || xof_read_reduced(&mut *xof);
        let mut ss = SecretScalar(UnsafeCell::new([xof(), xof()]) );
        ss.resplit_mut();
        ss
    }

    /// Multiply by a scalar.
    pub fn mul_by_challenge(&self, rhs: &F) -> F {
        let o = self.operate(|ss| (ss[0] * rhs) + (ss[1] * rhs) );
        self.resplit();
        o
    }

    /// Arkworks multiplies on the right since ark_ff is a dependency of ark_ec.
    /// but ark_ec being our dependency requires left multiplication here.
    fn mul_action<G: Group<ScalarField=F>>(&self, x: &mut G) {
        let mut y = x.clone();
        self.operate(|ss| {
            *x *= ss[0];
            y *= ss[1];
            *x += y;
        });
    }
}

impl<F: PrimeField> AddAssign<&SecretScalar<F>> for SecretScalar<F> {
    fn add_assign(&mut self, rhs: &SecretScalar<F>) {
        let lhs = self.0.get_mut();
        rhs.operate(|rhs| {
            lhs[0] += rhs[0];
            lhs[1] += rhs[1];
        });
    }
}

impl<F: PrimeField> Add<&SecretScalar<F>> for &SecretScalar<F> {
    type Output = SecretScalar<F>;
    fn add(self, rhs: &SecretScalar<F>) -> SecretScalar<F> {
        let mut lhs = self.risky_clone();
        lhs += rhs;
        lhs.resplit_mut();
        lhs
    }
}

/*
impl<G: Group> Mul<&G> for &SecretScalar<<G as Group>::ScalarField> {
    type Output = G;
    /// Arkworks multiplies on the right since ark_ff is a dependency of ark_ec.
    /// but ark_ec being our dependency requires left multiplication here.
    fn mul(self, rhs: &G) -> G {
        let mut rhs = rhs.clone();
        self.mul_action(&mut rhs);
        rhs
    }
}
*/

impl<C: AffineRepr> Mul<&C> for &SecretScalar<<C as AffineRepr>::ScalarField> {
    type Output = <C as AffineRepr>::Group;
    /// Arkworks multiplies on the right since ark_ff is a dependency of ark_ec.
    /// but ark_ec being our dependency requires left multiplication here.
    fn mul(self, rhs: &C) -> Self::Output {
        let o = self.operate(|lhs| rhs.mul(lhs[0]) + rhs.mul(lhs[1]));
        use ark_ec::CurveGroup;
        debug_assert_eq!(o.into_affine(), { let mut t = rhs.into_group(); self.mul_action(&mut t); t }.into_affine() );
        self.resplit();
        o
    }
}

