
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

pub VrfSignature: Debug,Clone,PartialEq,Eq,Hash,CanonicalSerialize,CanonicalDeserialize { }

/// IRTF hash-to-curve draft specifies hashing for a message
/// accompanied by applicaiton selected domain seperation tag.
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

    /// Actual signature of the VRF.  
    /// 
    /// In principle, VRFs could take and return `Vec<Self::InOut>`,
    /// like if used in a card gme where you play a variable number of
    /// cards in a round.  If so, this `Vec<VrfPreOut>` avoids `Signature`
    /// being an associated type constructor based on a const generic,
    /// but writing it this way shows the sizes.
    type Signature<const N: usize>: VrfSignature;

    fn vrf_verify<const N: usize>(
        &self,
        extra: Self::AssData,
        ios: &[Self::VrfInputMessage; N],
        signature: &Self::Signature,
    ) -> Result<[Self::InputOutput; N],&'static str>;  // Self::Vector<Self::InputOutput>;
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
    ) -> <Self::PublicKey as VrfPublicKey>::Signature<N>;
}

