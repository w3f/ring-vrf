use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::MontFp;
use ring::ring::Ring;

use crate::bls12_381;
use crate::ring::PADDING_POINT;

// KZG verification key formed using zcash powers of tau setup,
// see https://zfnd.org/conclusion-of-the-powers-of-tau-ceremony/
// This depends only on the trapdoor tau and doesn't change with the SRS size.
pub const ZCASH_KZG_VK: crate::ring::KzgVk = {
    const ZCASH_TAU_G2: bls12_381::G2Affine = {
        const TAU_G2_X_C0: bls12_381::Fq = MontFp!("186544079744757791750913777923182116923406997981176124505869835669370349308168084101869919858020293159217147453183");
        const TAU_G2_X_C1: bls12_381::Fq = MontFp!("2680951345815209329447762511030627858997446358927866220189443219836425021933771668894483091748402109907600527683136");
        const TAU_G2_Y_C0: bls12_381::Fq = MontFp!("2902268288386460594512721059125470579172313681349425350948444194000638363935297586336373516015117406788334505343385");
        const TAU_G2_Y_C1: bls12_381::Fq = MontFp!("1813420068648567014729235095042931383392721750833188405957278380281750025472382039431377469634297470981522036543739");
        const TAU_G2_X: bls12_381::Fq2 = bls12_381::Fq2::new(TAU_G2_X_C0, TAU_G2_X_C1);
        const TAU_G2_Y: bls12_381::Fq2 = bls12_381::Fq2::new(TAU_G2_Y_C0, TAU_G2_Y_C1);
        bls12_381::G2Affine::new_unchecked(TAU_G2_X, TAU_G2_Y)
    };
    crate::ring::KzgVk {
        g1: bls12_381::g1::Config::GENERATOR,
        g2: bls12_381::g2::Config::GENERATOR,
        tau_in_g2: ZCASH_TAU_G2,
    }
};

pub const EMPTY_RING_ZCASH_16: crate::ring::RingCommitment  = {
    const CX: bls12_381::G1Affine = {
        const CX_X: bls12_381::Fq = MontFp!("3788900533645096359019216841960589653729050156392657543253995350463234398678023194904690783533798180859113443129587");
        const CX_Y: bls12_381::Fq = MontFp!("3582602640224975303869289619528171841306894960147190839338637222834230941804329040350369300962553901480636730372581");
        bls12_381::G1Affine::new_unchecked(CX_X, CX_Y)
    };

    const CY: bls12_381::G1Affine = {
        const CY_X: bls12_381::Fq = MontFp!("275395450190015856550496699869027966473940409580082325014934185576731671390149219559463097372558226437269657531660");
        const CY_Y: bls12_381::Fq = MontFp!("3663288734506896245820179102192865221246127277945565853514629164665454948590285989938009769802061984318296406596594");
        bls12_381::G1Affine::new_unchecked(CY_X, CY_Y)
    };

    const SELECTOR: bls12_381::G1Affine = {
        const S_X: bls12_381::Fq = MontFp!("1782119914953303272451532413343785016217423941022111405224636116706617268932874941495968306638218277903118171292714");
        const S_Y: bls12_381::Fq = MontFp!("980603551794328446316569624808467604586898338411909681693214961643826527471799191709185815907315792552509777449194");
        bls12_381::G1Affine::new_unchecked(S_X, S_Y)
    };

    Ring::empty_unchecked(1 << 16, CX, CY, SELECTOR, PADDING_POINT)
};

pub const EMPTY_RING_ZCASH_9: crate::ring::RingCommitment  = {
    const CX: bls12_381::G1Affine = {
        const CX_X: bls12_381::Fq = MontFp!("3291131881719335745208408701681071363716236350417454999905110666318371537988666481391841675885214685977620333296347");
        const CX_Y: bls12_381::Fq = MontFp!("656646093535020120743664511096703186833125593035677837853779434938235484450936004914833523742524637066850726692849");
        bls12_381::G1Affine::new_unchecked(CX_X, CX_Y)
    };

    const CY: bls12_381::G1Affine = {
        const CY_X: bls12_381::Fq = MontFp!("1379935455078958073848938550933991225642174070456251938010549849263825750122860425278454316147982027674102683391035");
        const CY_Y: bls12_381::Fq = MontFp!("3310969786079377757118431956146881739794049489592156595529073696500104605627892596749867504817872693129039702247882");
        bls12_381::G1Affine::new_unchecked(CY_X, CY_Y)
    };

    const SELECTOR: bls12_381::G1Affine = {
        const S_X: bls12_381::Fq = MontFp!("2908850075820590559825558591796489926137468891350244723135070577033834833074699096095104618216690855741912718144719");
        const S_Y: bls12_381::Fq = MontFp!("436343574607707198583869582232412021753441754571435491281710311907340647898134029725340232367691953082908705963261");
        bls12_381::G1Affine::new_unchecked(S_X, S_Y)
    };

    Ring::empty_unchecked(1 << 9, CX, CY, SELECTOR, PADDING_POINT)
};


#[cfg(all(test, feature = "std"))]
mod tests {
    use ark_serialize::CanonicalDeserialize;
    use ring::ring::RingBuilderKey;

    use super::*;

    fn build_empty_ring(log_domain_size: usize) -> crate::ring::RingCommitment {
        let piop_params = crate::ring::make_piop_params(1 << log_domain_size);
        let vk = crate::ring::StaticVerifierKey::deserialize_uncompressed_unchecked(
            std::fs::read(format!("zcash-{}.vk", log_domain_size)).unwrap().as_slice()
        ).unwrap();
        let rbk = RingBuilderKey {
            lis_in_g1: vk.lag_g1,
            g1: ZCASH_KZG_VK.g1.into(),
        };
        crate::ring::RingCommitment::with_keys(
            &piop_params,
            &[],
            &rbk,
        )
    }

    #[test]
    fn check_empty_ring_16() {
        assert_eq!(EMPTY_RING_ZCASH_16, build_empty_ring(16));
    }

    #[test]
    fn check_empty_ring_9() {
        assert_eq!(EMPTY_RING_ZCASH_9, build_empty_ring(9));
    }
}
