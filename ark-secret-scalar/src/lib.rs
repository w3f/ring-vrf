// Copyright (c) 2019-2020 Web 3 Foundation

#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]

use core::ops::{Add,AddAssign,Mul};

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
#[derive(Zeroize)]
pub struct SecretScalar<F: PrimeField>([F; 2]);

impl<F: PrimeField> From<F> for SecretScalar<F> {
    fn from(value: F) -> Self {
        Self::from(&value)
    }
}

impl<F: PrimeField + Clone> From<&F> for SecretScalar<F> {
    fn from(value: &F) -> Self {
        let mut xof = Rng2Xof(getrandom_or_panic());
        let v1 = xof_read_reduced(&mut xof);
        let v2 = value.sub(v1);
        SecretScalar([v1, v2])
    }
}

impl<F: PrimeField> Clone for SecretScalar<F> {
    fn clone(&self) -> SecretScalar<F> {
        let mut secret = SecretScalar(self.0.clone());
        secret.resplit();
        secret
    }
}

impl<F: PrimeField> PartialEq for SecretScalar<F> {
    fn eq(&self, rhs: &SecretScalar<F>) -> bool {
        self.scalar() == rhs.scalar()
    }
}

impl<F: PrimeField> Eq for SecretScalar<F> {}

impl<F: PrimeField> Drop for SecretScalar<F> {
    fn drop(&mut self) { self.zeroize() }
}

impl<F: PrimeField> SecretScalar<F> {
    pub fn resplit(&mut self) {
        let mut xof = Rng2Xof(getrandom_or_panic());
        let x = xof_read_reduced(&mut xof);
        let selfy = &mut self.0;
        selfy[0] += &x;
        selfy[1] -= &x;
    }

    /// Internal clone which skips resplit.
    fn risky_clone(&self) -> SecretScalar<F> {
        SecretScalar(self.0.clone())
    }

    /// Initialize and unbiased `SecretScalar` from a `XofReaader`.
    pub fn from_xof<R: XofReader>(xof: &mut R) -> Self {
        let mut xof = || xof_read_reduced(&mut *xof);
        let mut ss = SecretScalar([xof(), xof()]);
        ss.resplit();
        ss
    }

    /// Multiply by a scalar.
    pub fn mul_by_challenge(&self, rhs: &F) -> F {
        self.scalar() * rhs
    }

    pub fn scalar(&self) -> F {
        self.0[0] + self.0[1]
    }

    /// Arkworks multiplies on the right since ark_ff is a dependency of ark_ec.
    /// but ark_ec being our dependency requires left multiplication here.
    fn mul_action<G: Group<ScalarField=F>>(&self, x: &mut G) {
        let mut y = x.clone();
        let selfy = &self.0;
        *x *= selfy[0];
        y *= selfy[1];
        *x += y;
    }
}

impl<F: PrimeField> AddAssign<&SecretScalar<F>> for SecretScalar<F> {
    fn add_assign(&mut self, rhs: &SecretScalar<F>) {
        let lhs = &mut self.0;
        let rhs = &rhs.clone().0;
        lhs[0] += rhs[0];
        lhs[1] += rhs[1];
    }
}

impl<F: PrimeField> Add<&SecretScalar<F>> for &SecretScalar<F> {
    type Output = SecretScalar<F>;

    fn add(self, rhs: &SecretScalar<F>) -> SecretScalar<F> {
        let mut lhs = self.risky_clone();
        lhs += rhs;
        lhs
    }
}

impl<C: AffineRepr> Mul<&C> for &SecretScalar<<C as AffineRepr>::ScalarField> {
    type Output = <C as AffineRepr>::Group;

    /// Arkworks multiplies on the right since ark_ff is a dependency of ark_ec.
    /// but ark_ec being our dependency requires left multiplication here.
    fn mul(self, rhs: &C) -> Self::Output {
        let lhs = &self.clone().0;
        let o = rhs.mul(lhs[0]) + rhs.mul(lhs[1]);
        use ark_ec::CurveGroup;
        debug_assert_eq!(o.into_affine(), { let mut t = rhs.into_group(); self.mul_action(&mut t); t }.into_affine() );
        o
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_377::Fr;
    use ark_ff::MontFp;
    use ark_std::fmt::Debug;

    impl<F: PrimeField + Debug> Debug for SecretScalar<F> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            let selfy = &self.0;
            f.debug_tuple("SecretScalar")
                .field(&selfy[0])
                .field(&selfy[1])
                .finish()
        }
    }

    #[test]
    fn from_single_scalar_works() {
        let value: Fr = MontFp!("123456789");

        let mut secret = SecretScalar::from(value);
        assert_eq!(value, secret.scalar());

        secret.resplit();
        assert_eq!(value, secret.scalar());

        let secret2 = secret.clone();
        assert_ne!(secret.0[0], secret2.0[0]);
        assert_ne!(secret.0[1], secret2.0[1]);
        assert_eq!(secret, secret2);
    }

    #[test]
    fn mul_my_challenge_works() {
        let value: Fr = MontFp!("123456789");
        let secret = SecretScalar::from(value);

        let factor = Fr::from(3);
        let result = secret.mul_by_challenge(&factor);
        assert_eq!(result, value * factor);
    }
}
