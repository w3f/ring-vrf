
type K = BLS12_377::G1Affine;
type H = BLS12_377::G1Affine;

// pub const VRF_PREOUT_LENGTH: usize = ???;


pub type VrfInput = vrf_ad_kc::VrfInput<H>;
pub type VrfPreOut = vrf_ad_kc::VrfPreOut<H>;
pub type VrfInOut = vrf_ad_kc::VrfInOut<H>;

pub type PedersenVrf = vrf_ad_kc::PedersenVrf<K,H>;
pub type PedersenVrfSignature = vrf_ad_kc::Signature<PedersenVrf>;

pub const PEDERSEN_VRF: PedersenVrf = PedersenVrf::new(???,???);


pub type ThinVrf = vrf_ad_kc::ThinVrf<H>;
pub type ThinVrfSignature = vrf_ad_kc::Signature<ThinVrf<H>>;

// We've deref polymorphism from PedersenVrf to ThinVrf, but
// it does not work if H and K differ.

pub const THIN_VRF: PedersenVrf = PedersenVrf::new(???,???);


pub struct PublicKey {
    /// 
    pedersen_publickey: vrf_ad_kc::PublicKey<H>,
    ///
    thin_publickey: vrf_ad_kc::PublicKey<K>,
    /// Proves equivelence between the pedersen and thin public keys.
    pedvrf_signature: vrf_ad_kc::Signature<PedersenVrf<H,K,1>>,
    // We'd need a more complex singleton ring_proof here for Jeff's flavor.
}


pub struct SecretKey {
    pedersen_vrf: PedersenVrfSignature,
    ///
    ring_opening: ring_proof::???
}


