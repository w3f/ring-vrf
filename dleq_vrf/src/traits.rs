//! # Elliptic curve based VRFs trait abstractions
//!
//! We provide trait abstractions suitable for usage with most
//! elliptic curve based verifiable random functions (EC VRFs).
//! 
//! We support some ring verifiable random functions (ring VRFs) too,
//! because under the hood some of these employ constructions very
//! similar to EC VRFs
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
//! TODO:  We have not evaluated if these traits mesh wqell with
//! batch verification or threshold multi-signed VRFs.
//! 
//! TODO:  `IntoTranscript` might not correctly abstract signing for
//! a remote signer.


pub use crate::error;
pub use crate::vrf::{self, VrfInput, VrfPreOut, VrfInOut};


type VrfResult<T> = Result<T,&'static str>


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
    /// We do not have the ideal trait interface here because
    /// a remote signer can do no validation of a `VrfInput<H>`,
    /// so this method could become depricated in future.
    /// We suggest users avoid this method, and invoke only
    /// `vrf_inout`, but implementors could still supply this
    /// method for now.
    pub fn vrf_preout<H>(&self, input: &VrfInput<H>) -> VrfPreOut<H>;

    /// Create an `InputOutput` for usage both in signing as well as
    /// in protocol buisness logic.
    /// 
    /// Always a thin wrapper around `SecretKey::vrf_inout` defined in
    /// the `dleq_vrf::vrf`, but our secret key remains abstract here.
    fn vrf_inout(&self, input: impl IntoVrfInput<H>) -> VrfInOut<H> {
        let input = input.into_vrf_input();
        let preoutput = self.vrf_preout(&input);
        VrfInOut { input, preoutput }
    }
}

/// TODO:  We should delegate the `SecretKey::{vrf_preout, vrf_inout}`
/// in the `vrf` module to these ones, so they'll always agree.
impl<H,K> EcVrfSecret<H> for SecretKey<K>
where K: AffineRepr, H: AffineRepr<ScalarField = K::ScalarField>,
{
    fn vrf_preout<H>(&self, input: &vrf::VrfInput<H>) -> VrfPreOut<H> {
        VrfPreOut( (&self.key * &input.0).into_affine() )
    }
}


/// VRF protocol parameters, flavor, etc. 
pub trait EcVrf {
    /// Target group for hash-to-curve
    type H: AffineRepr;
    /// Detached signature aka proof type created by the VRF
    type VrfProof: Debug,Clone,PartialEq,Eq,Hash,CanonicalSerialize,CanonicalDeserialize;
}

pub type EcVrfInput<V> = VrfInput<<V as EcVrfIO>::H>;
pub type EcVrfPreOut<V> = VrfPreOut<<V as EcVrfIO>::H>;
pub type EcVrfInOut<V> = VrfInOut<<V as EcVrfIO>::H>;

#[derive(Debug,Clone,PartialEq,Eq,Hash,CanonicalSerialize,CanonicalDeserialize)]
pub struct VrfSignature<V: EcVrfProof, const N: usize> {
    pub proof: V::VrfProof,
    pub preouts: [VrfPreOut<V>; N],
}

#[derive(Debug,Clone,PartialEq,Eq,Hash,CanonicalSerialize,CanonicalDeserialize)]
pub struct VrfSignatureVec<V: EcVrfProof> {
    pub proof: V::VrfProof,
    pub preouts: Vec<VrfPreOut<V>>,
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
pub trait EcVrfSigner: EcVrf+Borrow<Secret> {
    type Error;
    type Secret: EcVrfSecret<Self::H>;

    fn vrf_sign_detached(
        &self,
        t: impl IntoTranscript,
        ios: &[VrfInOut<Self>]
    ) -> VrfResult<<Self as EcVrf>::VrfProof>;

    /// VRF signature for a fixed number of input-output pairs
    fn vrf_sign<const N: usize>(
        &self,
        t: impl IntoTranscript,
        ios: &[VrfInOut<Self>; N]
    ) -> VrfResult<VrfSignature<Self,N>>
    {
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
    fn vrf_sign_one<I,T,F>(&self, input: I, check: F) -> VrfResult<VrfSignature<Self,1>>
    where
        I: IntoVrfInput<H>,
        T: IntoTranscript,
        F: FnMut(VrfInOut<H>) -> VrfResult<T>,
    {
        let io = self.borrow().vrf_inout(input);
        let t = check(io) ?;
        let proof = self.vrf_sign_detached(t,&[io]) ?;
        let preouts = core::array::from_fn(|i| ios[i].preoutput.clone());
        Ok(VrfSignature { preouts, proof })
    }

    /// VRF signature for a variable number of input-output pairs.
    fn vrf_sign_vec(
        &self,
        t: impl IntoTranscript,
        ios: &[VrfInOut<Self>]
    ) -> VrfResult<VrfSignatureVec<Self>>
    {
        let proof = self.vrf_sign_detached(t,ios) ?;
        let preouts = ios.iter().map(|io| io.preoutput.clone()).collect();
        Ok(VrfSignatureVec { preouts, proof })
    }
}

impl<K: AffineRepr> EcVrf for SecretKey<K> {
    type H = K;
    type VrfProof = crate::Signature<crate::ThinVrf<K>>;
}

impl<K: AffineRepr> EcVrfSecret<K> for SecretKey<K> {
    type Error = ();
    type Secret = Self;
    fn vrf_sign_detached(
        &self,
        t: impl IntoTranscript,
        ios: &[VrfInOut<Self>]
    ) -> VrfResult<<Self as EcVrf>::VrfProof>
    {
        Ok(self.sign_thin_vrf(t,ios))
    }
}


/// VRF verifier, like a public key or ring commitment. 
/// 
/// Inherent methods and other traits being used here:
/// `IntoTranscript`, `vrf::{IntoVrfInput, VrfPreOut::attach_input, VrfInOut}`
pub trait EcVrfVerifier: EcVrfProof {
    type Error: From<error::SignatureError>;
    fn vrf_verify_detached<'a>(
        &self,
        t: impl IntoTranscript,
        ios: &'a [VrfInOut<Self>],        
        signature: &<Self as EcVrf>VrfProof,
    ) -> VrfResult<&'a [VrfInOut<K>]>;

    fn vrf_verify<const N: usize>(
        &self,
        t: impl IntoTranscript,
        inputs: impl IntoIterator<Item = impl IntoVrfInput<Self::H>>,
        signature: &VrfSignature<V,N>,
    ) -> Result<[VrfInOut<Self>; N],Error>
    {
        let mut inputs = inputs.into_iter();
        let mut preouts = signature.preouts.iter().cloned();
        let mut cb = |_| preouts.next().unwrap().attach_input(inputs.next().unwrap());
        let ios: [VrfInOut<Self>; N] = core::array::from_fn(cb);
        self.vrf_verify_detached(t,ios.as_slice(),&signature.proof) ?;
        Ok(ios)
    }

    fn vrf_verify_vec(
        &self,
        t: impl IntoTranscript,
        inputs: impl IntoIterator<Item = impl IntoVrfInput<Self::H>>,
        signature: &VrfSignatureVec<V>,
    ) -> Result<Vec<VrfInOut<Self>>,Error>
    {
        let ios: Vec<VrfInOut<Self>> = signature.preouts.iter()
        .zip(inputs).map(|preout,input| preout.attach_input(input))
        .collect();
        self.vrf_verify_detached(t,ios.as_slice(),&signature.proof) ?;
        Ok(ios)
    }
}

impl<K: AffineRepr> EcVrf<K> for (&ThinVrf<K>,&PublicKey<K>) {
    type H = K;
    type VrfProof = crate::Signature<crate::ThinVrf<K>>;
}

impl<K: AffineRepr> EcVrfVerifier<K> for (&ThinVrf<K>,&PublicKey<K>) {
    type Error = error::SignatureError;
    fn vrf_verify_detached<'a>(
        &self,
        t: impl IntoTranscript,
        ios: &'a [VrfInOut<Self>],        
        signature: &<Self as EcVrf>VrfProof,
    ) -> Result<&'a [VrfInOut<K>],Error>
    {
        self.0.verify_thin_vrf(t,ios,self.1,signature)?
    }
}

