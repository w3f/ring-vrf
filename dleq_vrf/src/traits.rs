//! # Elliptic curve based VRF trait abstractions
//!
//! We provide trait abstractions suitable for usage with many
//! elliptic curve based verifiable random functions (EC VRFs).
//! We support some ring verifiable random functions (ring VRFs) too,
//! because under the hood some of these employ constructions very
//! similar to EC VRFs.
//! 
//! We assume all VRFs support arbitrarily many input-output pairs,
//! given by elliptic curve points all on the same curve.  We also
//! assume all VRFs provide sign some associated extra message aka
//! transcript, not part of their inputs.  
//! 
//! Not all VRFs provide these features.  Some non-examples:
//! One-layer XMMS is a nice post-quantum VRF.
//! RSA-FDH is an extremely fast VRF if properly configured.
//! BLS is a terrible VRF but winds up being popularized.
//! 
//! TODO:  We have not evaluated if these traits mesh well with
//! batch verification or threshold multi-signed VRFs.
//! 
//! TODO:  `IntoTranscript` might not correctly abstract signing for
//! a remote signer.


use ark_std::{borrow::Borrow, fmt, vec::Vec};

use ark_serialize::{CanonicalSerialize,CanonicalDeserialize}; // Valid
use ark_ec::{AffineRepr,CurveGroup};

pub use crate::{
    IntoTranscript,SecretKey,error,
    vrf::{self, IntoVrfInput, VrfInput, VrfPreOut, VrfInOut},
};

// Helpers types

pub type EcAffineRepr<V> = <V as EcVrfVerifier>::H;
pub type EcVrfInput<V> = VrfInput<<V as EcVrfVerifier>::H>;
pub type EcVrfPreOut<V> = VrfPreOut<<V as EcVrfVerifier>::H>;
pub type EcVrfInOut<V> = VrfInOut<<V as EcVrfVerifier>::H>;
pub type EcVrfProof<V> = <V as EcVrfVerifier>::VrfProof;

type VrfSignatureFor<V, const N: usize> = VrfSignature<EcVrfProof<V>, EcAffineRepr<V>, N>;
type VrfSignatureVecFor<V> = VrfSignatureVec<EcVrfProof<V>, EcAffineRepr<V>>;

/// Bound we require for a generic  Elliptic Curve signature type.
pub trait EcVrfProofBound: fmt::Debug + Sync + Send + Clone + Eq + PartialEq + CanonicalSerialize + CanonicalDeserialize {}


#[derive(Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct VrfSignature<P: EcVrfProofBound, H: AffineRepr, const N: usize> {
    pub proof: P,
    pub preouts: [VrfPreOut<H>; N],
}

impl<P: EcVrfProofBound, H: AffineRepr, const N: usize> fmt::Debug for VrfSignature<P, H, N> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "VrfSignature {{ proof: {:?}, preouts: {:?} }}", &self.proof, &self.preouts)
	}
}

impl<P: EcVrfProofBound, H: AffineRepr, const N: usize> VrfSignature<P, H, N> {
    pub fn attach_inputs(
        &self,
        inputs: impl IntoIterator<Item = impl IntoVrfInput<H>>
    ) -> [VrfInOut<H>; N]
    {
        let mut inputs = inputs.into_iter();
        let mut preouts = self.preouts.iter().cloned();
        let cb = |_| preouts.next().unwrap().attach_input(inputs.next().unwrap());
        core::array::from_fn(cb)
    }

    pub fn vrf_verify<V: EcVrfVerifier<VrfProof = P, H = H>>( 
        &self,
        t: impl IntoTranscript,
        inputs: impl IntoIterator<Item = impl IntoVrfInput<H>>,
        verifier: &V
    ) -> Result<[VrfInOut<H>; N], V::Error>
    {
        verifier.vrf_verify(t, inputs, self)
    }
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct VrfSignatureVec<P: EcVrfProofBound, H: AffineRepr> {
    pub proof: P,
    pub preouts: Vec<VrfPreOut<H>>,
}

impl<P: EcVrfProofBound, H: AffineRepr> fmt::Debug for VrfSignatureVec<P, H> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "VrfSignature {{ proof: {:?}, preouts: {:?} }}", &self.proof, &self.preouts)
	}
}

impl<P: EcVrfProofBound, H: AffineRepr> VrfSignatureVec<P, H> {
    pub fn attach_inputs(
        &self,
        inputs: impl IntoIterator<Item = impl IntoVrfInput<H>>
    ) -> Vec<VrfInOut<H>>
    {
        self.preouts.iter().zip(inputs)
            .map(|(preout,input)| preout.attach_input(input))
            .collect()
    }

    pub fn vrf_verify<V: EcVrfVerifier<VrfProof = P, H = H>>( 
        &self,
        t: impl IntoTranscript,
        inputs: impl IntoIterator<Item = impl IntoVrfInput<H>>,
        verifier: &V,
    ) -> Result<Vec<EcVrfInOut<V>>, V::Error>
    {
        verifier.vrf_verify_vec(t, inputs, self)
    }
}

/// VRF secret key.
/// 
/// Inherent methods and other traits being used here:
/// `vrf::{IntoVrfInput, VrfInOut}`
/// 
/// We support multiple pre-output curves for the same secret key
/// vai this formulation, which maybe overkill for polkadot, but
/// makes some sense.
pub trait EcVrfSecret<H: AffineRepr> {
    /// Compute VRF pre-output from secret key and input point.
    /// 
    /// Implementers may provide this method, but users must not
    /// invoke this method directly.  Inkove `vrf_inout` instead.
    /// 
    /// A remote signer can do no validation of a `VrfInput<H>`,
    /// so remote signers should make this method `panic!`,
    /// and instead implement `vrf_inout` using reflection, meaning
    /// their `vrf_inout` should work for their expected types,
    /// but `panic!` for unexpected types, including `VrfInput<H>`.
    fn vrf_preout(&self, input: &VrfInput<H>) -> VrfPreOut<H>;

    /// Create an `InputOutput` for usage both in signing as well as
    /// in protocol buisness logic.
    /// 
    /// Always a thin wrapper around `SecretKey::vrf_inout` defined in
    /// the `dleq_vrf::vrf`, but our secret key remains abstract here.
    fn vrf_inout(&self, input: impl IntoVrfInput<H>) -> VrfInOut<H> {
        let input = input.into_vrf_input();
        let preoutput = EcVrfSecret::vrf_preout(self,&input);
        VrfInOut { input, preoutput }
    }
}

/// We delegate the `SecretKey::{vrf_preout, vrf_inout}` in the `vrf`
/// module to these ones, which asures agreement.
impl<H,K> EcVrfSecret<H> for SecretKey<K>
    where K: AffineRepr, H: AffineRepr<ScalarField = K::ScalarField>,
{
    fn vrf_preout(&self, input: &vrf::VrfInput<H>) -> VrfPreOut<H> {
        VrfPreOut( (&self.key * &input.0).into_affine() )
    }
}


/// VRF verifier, like a public key or ring commitment. 
/// 
/// Inherent methods and other traits being used here:
/// `IntoTranscript`, `vrf::{IntoVrfInput, VrfPreOut::attach_input, VrfInOut}`
pub trait EcVrfVerifier {
    /// Target group for hash-to-curve
    type H: AffineRepr;

    /// Detached signature aka proof type created by the VRF
    type VrfProof: EcVrfProofBound;

    /// Verification failures
    type Error: From<error::SignatureError>; // = error::SignatureError;

    fn vrf_verify_detached(
        &self,
        t: impl IntoTranscript,
        ios: &[VrfInOut<Self::H>],        
        signature: &Self::VrfProof,
    ) -> Result<(), Self::Error>;

    fn vrf_verify<const N: usize>(
        &self,
        t: impl IntoTranscript,
        inputs: impl IntoIterator<Item = impl IntoVrfInput<Self::H>>,
        signature: &VrfSignature<Self::VrfProof, Self::H, N>,
    ) -> Result<[VrfInOut<Self::H>; N], Self::Error> {
        let ios: [VrfInOut<Self::H>; N] = signature.attach_inputs(inputs);
        self.vrf_verify_detached(t,ios.as_slice(),&signature.proof) ?;
        Ok(ios)
    }

    fn vrf_verify_vec(
        &self,
        t: impl IntoTranscript,
        inputs: impl IntoIterator<Item = impl IntoVrfInput<Self::H>>,
        signature: &VrfSignatureVec<Self::VrfProof, Self::H>,
    ) -> Result<Vec<VrfInOut<Self::H>>, Self::Error> {
        let ios = signature.attach_inputs(inputs);
        self.vrf_verify_detached(t,ios.as_slice(),&signature.proof) ?;
        Ok(ios)
    }
}


/// VRF signer, includes the secret key, but sometimes the ring opening too.
/// 
/// We do not favor pseduo-convenience methods like schnorrkel's
/// `sign_extra_after_check`.  We've found too many VRF protocols need
/// multiple input-output pairs, making convenience methods inconvenient.
/// In practice, one should typically invoke `EcVrfSecret::vrf_inout`
/// seperately for each input, run buisness logic upon the `VrfInOut`s
/// they return, and then pass whatever `VrfInOut`s require signing to
/// `vrf_sign*`.
/// 
/// We do provide an analogous `vrf_sign_one` method for pedagogy, but
/// we also provide convenience methods to handle multiple input groupings
/// instead of doing multiple single input flavors.
/// 
/// Inherent methods and other traits being used here:
/// `IntoTranscript`, `vrf::{VrfInOut, VrfPreOut}`
pub trait EcVrfSigner: Borrow<Self::Secret> {
    /// Verifier type
    /// 
    /// We only fetch `V::H` and `V::VrfProof` via this, so if your
    /// verifier contains lifetimes then approximate them by `'static`.
    type V: EcVrfVerifier;

    /// Signer failures, usually `!` but otherwise for ring VRFs
    type Error;  // = !;

    /// Actual secret key type, possible `Self` for regular VRFs
    /// but not for ring VRFs or simlar.
    type Secret: EcVrfSecret<<Self::V as EcVrfVerifier>::H>;

    fn vrf_sign_detached(
        &self,
        t: impl IntoTranscript,
        ios: &[VrfInOut<<Self::V as EcVrfVerifier>::H>]
    ) -> Result<<Self::V as EcVrfVerifier>::VrfProof, Self::Error>;

    /// VRF signature for a fixed number of input-output pairs
    fn vrf_sign<const N: usize>(
        &self,
        t: impl IntoTranscript,
        ios: &[EcVrfInOut<Self::V>; N]
    ) -> Result<VrfSignatureFor<Self::V, N>, Self::Error> {
        let proof = self.vrf_sign_detached(t,ios) ?;
        let preouts = core::array::from_fn(|i| ios[i].preoutput.clone());
        Ok(VrfSignature { preouts, proof })
    }

    /// VRF signature for a single input-output pair
    /// 
    /// We provide this analog of schnorrkel's `sign_extra_after_check`
    /// more for pedagogy than for convenience.  It demonstrates choosing
    /// whether we sign the VRF, and what else we sign in its transcript,
    /// after examining the VRF output.
    fn vrf_sign_one<I,T,F>(&self, input: I, mut check: F) -> Result<VrfSignatureFor<Self::V, 1>, Self::Error>
    where
        I: IntoVrfInput<<Self::V as EcVrfVerifier>::H>,
        T: IntoTranscript,
        F: FnMut(&EcVrfInOut<Self::V>) -> Result<T,Self::Error>,
    {
        let io = self.borrow().vrf_inout(input);
        let t = check(&io) ?;
        self.vrf_sign(t,&[io])
    }

    /// VRF signature for a variable number of input-output pairs.
    fn vrf_sign_vec(
        &self,
        t: impl IntoTranscript,
        ios: &[VrfInOut<<Self::V as EcVrfVerifier>::H>]
    ) -> Result<VrfSignatureVecFor<Self::V>, Self::Error>
    {
        let proof = self.vrf_sign_detached(t,ios) ?;
        let preouts = ios.iter().map(|io| io.preoutput.clone()).collect();
        Ok(VrfSignatureVec { preouts, proof })
    }
}
