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
//! TODO:  `IntoTranscript` does not correctly abstract signing for
//! a remote signer.


pub use crate::vrf;

type VrfResult<T> = Result<T,&'static str>


/// VRF protocol parameters, flavor, etc. 
pub trait EcVrf {
    /// Target group for hash-to-curve
    type H: AffineRepr;

    /// Detached signature aka proof type created by the VRF
    type VrfProof: Debug,Clone,PartialEq,Eq,Hash,CanonicalSerialize,CanonicalDeserialize;
}

type VrfInput<V> = crate::vrf::VrfInput<<V as EcVrf>::H>;
type VrfPreOut<V> = crate::vrf::VrfPreOut<<V as EcVrf>::H>;
type VrfInOut<V> = crate::vrf::VrfInOut<<V as EcVrf>::H>;

#[derive(Debug,Clone,PartialEq,Eq,Hash,CanonicalSerialize,CanonicalDeserialize)]
pub struct VrfSignature<V: EcVrf, const N: usize> {
    pub proof: V::VrfProof,
    pub preouts: [VrfPreOut<V>; N],
}

#[derive(Debug,Clone,PartialEq,Eq,Hash,CanonicalSerialize,CanonicalDeserialize)]
pub struct VrfSignatureVec<V: EcVrf> {
    pub proof: V::VrfProof,
    pub preouts: Vec<VrfPreOut<V>>,
}

/// VRF verifier, like a public key or ring commitment. 
/// 
/// Inherent methods and other traits being used here:
/// `IntoTranscript`, `vrf::{IntoVrfInput, VrfPreOut::attach_input, VrfInOut}`
pub trait EcVrfVerifier: EcVrf {
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
    ) -> VrfResult<[VrfInOut<Self>; N]>
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
    ) -> VrfResult<Vec<VrfInOut<Self>>>
    {
        let ios: Vec<VrfInOut<Self>> = signature.preouts.iter()
        .zip(inputs).map(|preout,input| preout.attach_input(input))
        .collect();
        self.vrf_verify_detached(t,ios.as_slice(),&signature.proof) ?;
        Ok(ios)
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
pub trait EcVrfSecret<V: EcVrf> {
    /// Create an `InputOutput` for usage both in signing as well as
    /// in protocol buisness logic.
    /// 
    /// Always a thin wrapper around `SecretKey::vrf_inout` defined in
    /// the `dleq_vrf::vrf`, but our secret key remains abstract here.
    fn vrf_inout(&self, input: impl IntoVrfInput<<V as EcVrf>::H>) -> VrfInOut<V>;
}

/// VRF signer, includes the secret key, but sometimes the ring opening too.
/// 
/// We do not provide pseduo-convenience methods like schnorrkel's
/// `sign_extra_after_check`.  We've discovered too many VRF protocols
/// need multiple input-output pairs, which makes convenience methods
/// impossible.  instead, you should invoke `EcVrfSecret::vrf_inout`
/// seperately for each input, run your buisness logic upon its output,
/// and then pass whatever requires signing to `vrf_sign*`.  
/// We do have convenience methods to handle multiple input groupings.
/// 
/// Inherent methods and other traits being used here:
/// `IntoTranscript`, `vrf::{VrfInOut, VrfPreOut}`
pub trait EcVrfSigner: EcVrf+Deref<Target=Secret> {
    type Secret: EcVrfSecret<Self>;

    fn vrf_sign_detached(
        &self,
        t: impl IntoTranscript,
        ios: &[VrfInOut<Self>]
    ) -> VrfResult<<Self as EcVrf>::VrfProof>;

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

