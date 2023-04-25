
//! # Elliptic curve based VRFs trait abstractions
//!
//! Not all VRFs fit these.  Some like RSA-FDH, BLS, or one-layer XMMS
//! have `VrfPublicKey::AssData = ()` and require `N=1` everywhere, or
//! do not even use hash-to-curve.
//!
//! RSA-FDH and BLS are useless, but one-layer XMMS is post-quantum,
//! and thus useful if we wants to evaluate the cost of making the
//! polkadot consensus post-quantum.  


pub trait VrfInputOutput: Clone,PartialEq,Eq {
    fn vrf_output_bytes<const LEN: usize>(&self, context: &[u8]) -> [u8; LEN];
}

/// IRTF hash-to-curve draft specifies hashing for a message
/// accompanied by applicaiton selected domain seperation tag.
#[derive(Debug,Clone,PartialEq,Eq,Hash)]
pub struct VrfInputMessage<'a> {
    domain: &'a [u8],
    message: &'a [u8],
}

pub trait VrfPublicKey: Debug,Clone,PartialEq,Eq,Hash,CanonicalSerialize,CanonicalDeserialize {
    /// Associated data aka extra non-input message signed by the VRF,
    /// often a mutable borrow of some Fiat-Shamir transcript if designed
    /// for usage inside larger zk proof protocols.
    type AssData<'a>;

    /// Abstracted (Input,PreOutput) from which we compute actual outputs.
    /// Input to sign.  Returned by verify.
    type InputOutput: VrfInputOutput;

    type VrfPreOutput: Debug,Clone,PartialEq,Eq,Hash,CanonicalSerialize,CanonicalDeserialize;
    type VrfProof: Debug,Clone,PartialEq,Eq,Hash,CanonicalSerialize,CanonicalDeserialize;
    
    fn vrf_verify<const N: usize>(
        &self,
        extra: Self::AssData,
        ios: &[Self::VrfInputMessage; N],
        signature: &Self::Signature,
    ) -> Result<[Self::InputOutput; N],&'static str>;

    fn vrf_verify_vec(
        &self,
        extra: Self::AssData,
        ios: &[Self::VrfInputMessage],
        signature: &Self::Signature,
    ) -> Result<Vec<Self::InputOutput>,&'static str>;
}

#[derive(Debug,Clone,PartialEq,Eq,Hash,CanonicalSerialize,CanonicalDeserialize)]
pub struct VrfSignature<PK: VrfPublicKey, const N: usize> {
    pub proof: PK::VrfProof,
    pub preouts: [PK::VrfPreOutput; N],
}

#[derive(Debug,Clone,PartialEq,Eq,Hash,CanonicalSerialize,CanonicalDeserialize)]
pub struct VrfSignatureVec<PK: VrfPublicKey> {
    pub proof: PK::VrfProof,
    pub preouts: Vec<PK::VrfPreOutput>,
}

pub trait VrfSecretKey: Into<Self::PublicKey> {
    type PublicKey: VrfPublicKey;

    /// Create an `InputOutput` for usage both in signing and in 
    fn vrf_inout(
        &self,
        input: &<Self::PublicKey as VrfPublicKey>::VrfInputMessage
    ) -> <Self::PublicKey as VrfPublicKey>::InputOutput;

    fn vrf_sign<const N: usize>(
        &self,
        extra: <Self::PublicKey as VrfPublicKey>::AssData,
        ios: &[<Self::PublicKey as VrfPublicKey>::InputOutput; N]
    ) -> Signature<Self::PublicKey,N>;

    fn vrf_sign(
        &self,
        extra: <Self::PublicKey as VrfPublicKey>::AssData,
        ios: &[<Self::PublicKey as VrfPublicKey>::InputOutput; N]
    ) -> SignatureVec<Self::PublicKey>;
}

