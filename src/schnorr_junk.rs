
impl SecretKey {

    /// Run our Schnorr VRF on one single input, producing the output
    /// and correspodning Schnorr proof.
    /// You must extract the `VRFPreOut` from the `VRFInOut` returned.
    pub fn vrf_sign_simple<CW,PD>(&self, input: VRFInput)
     -> (VRFInOut, VRFProof<VRFPreOut,CW,PD>, PD::Unblinding)
    where
        CW: NewChallengeOrWitness,
        PD: NewPedersenDeltaOrPublicKey,
    {
        self.vrf_sign_first(input, no_extra())
    }

    /// Run our Schnorr VRF on one single input and an extra message 
    /// transcript, producing the output and correspodning Schnorr proof.
    /// You must extract the `VRFPreOut` from the `VRFInOut` returned.
    ///
    /// There are schemes like Ouroboros Praos in which nodes evaluate
    /// VRFs repeatedly until they win some contest.  In these case,
    /// you should probably use `vrf_sign_after_check` to gain access to
    /// the `VRFInOut` from `vrf_create_hash` first, and then avoid
    /// computing the proof whenever you do not win. 
    pub fn vrf_sign_first<T,CW,PD>(&self, input: VRFInput, extra: T)
     -> (VRFInOut, VRFProof<VRFPreOut,CW,PD>, PD::Unblinding)
    where
        T: SigningTranscript,
        CW: NewChallengeOrWitness,
        PD: NewPedersenDeltaOrPublicKey,
    {
        let inout = input.to_inout(self);
        let (proof, pd) = self.dleq_proove(extra, &inout, rand_hack());
        (inout, proof, pd)
    }


    /*

    /// Run VRF on one single input transcript, producing the outpus
    /// and correspodning short proof.
    ///
    /// There are schemes like Ouroboros Praos in which nodes evaluate
    /// VRFs repeatedly until they win some contest.  In these case,
    /// you should probably use vrf_sign_n_check to gain access to the
    /// `VRFInOut` from `vrf_create_hash` first, and then avoid computing
    /// the proof whenever you do not win. 
    pub fn vrf_sign(&self, input: VRFInput<E>)
     -> (VRFInOut<E>, VRFProof<E>, VRFProofBatchable<E,PD>)
    {
        self.vrf_sign_extra(input, Transcript::new(b"VRF"))
    }

    /// Run VRF on one single input transcript and an extra message transcript, 
    /// producing the outpus and correspodning short proof.
    pub fn vrf_sign_extra<T>(&self, input: VRFInput<E>, extra: T)
     -> (VRFInOut<E>, VRFProof<E>, VRFProofBatchable<E,PD>)
    where T: SigningTranscript,
    {
        let p = input.to_inout(self);
        let (proof, unblinding) = self.dleq_proove(extra, &p, rand_hack());
        (p, proof, unblinding)
    }

    /// Run VRF on one single input transcript, producing the outpus
    /// and correspodning short proof only if the result first passes
    /// some check.
    ///
    /// There are schemes like Ouroboros Praos in which nodes evaluate
    /// VRFs repeatedly until they win some contest.  In these case,
    /// you might use this function to short circuit computing the full
    /// proof.
    pub fn vrf_sign_after_check<F>(&self, input: VRFInput<E>, mut check: F)
     -> Option<(VRFInOut<E>, VRFProof<E>, VRFProofBatchable<E,PD>)>
    where F: FnMut(&VRFInOut<E>) -> bool,
    {
        self.vrf_sign_extra_after_check( input, |io| if check(io) { Some(Transcript::new(b"VRF")) } else { None })
    }

    /// Run VRF on one single input transcript, producing the outpus
    /// and correspodning short proof only if the result first passes
    /// some check, which itself returns an extra message transcript.
    pub fn vrf_sign_extra_after_check<T,F>(&self, input: VRFInput<E>, mut check: F)
     -> Option<(VRFInOut<E>, VRFProof<E>, VRFProofBatchable<E,PD>)>
    where T: SigningTranscript,
          F: FnMut(&VRFInOut<E>) -> Option<T>,
    {
        let p = input.to_inout(self);
        let extra = check(&p) ?;
        let (proof, unblinding) = self.dleq_proove(extra, &p, rand_hack());
        Some((p, proof, unblinding))
    }

    */

    /// Run VRF on several input transcripts, producing their outputs
    /// and a common short proof.
    ///
    /// We merge the VRF outputs using variable time arithmetic, so
    /// if even the hash of the message being signed is sensitive then
    /// you might reimplement some constant time variant.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub fn vrfs_sign_simple<T,CW,PD,B,I>(&self, ts: I)
     -> (Box<[VRFInOut]>, VRFProof<(),CW,PD>, PD::Unblinding)
    where
        CW: NewChallengeOrWitness,
        PD: NewPedersenDeltaOrPublicKey,
        B: Borrow<VRFInput>,
        I: IntoIterator<Item=B>,
    {
        self.vrfs_sign_extra(ts, Transcript::new(b"VRF"))
    }
}



impl<PD> VRFProof<VRFInOut,Individual,PD>
where PD: PedersenDeltaOrPublicKey+Clone,
{
    /// Verify VRF proof for one single input transcript and corresponding output.
    pub fn vrf_verify_simple(&self)
     -> SignatureResult<(VRFInOut,VRFProof<VRFPreOut,Batchable,PD>)>
    {
        self.vrf_verify(no_extra())
    }
}




/*
/// Batch verify DLEQ proofs where the public keys were held by
/// different parties.
///
/// We first reconstruct the `c`s present in the `VRFProof`s but absent
/// in the `VRFProofBatchable`s, using `shorten_dleq`.  We then verify
/// the `R` and `Hr` components of the `VRFProofBatchable`s using the
/// two equations a normal verification uses to discover them.
/// We do this by delinearizing both verification equations with
/// random numbers.
///
/// TODO: Assess when the two verification equations should be
/// combined, presumably by benchmarking both forms.  At smaller batch
/// sizes then we should clearly benefit form the combined form, but
/// bany combination doubles the scalar by scalar multiplicications
/// and hashing, so large enough batch verifications should favor two
/// seperate calls.
#[cfg(any(feature = "alloc", feature = "std"))]
#[allow(non_snake_case)]
pub fn vrf_verify_batch(
    inouts: &[VRFInOut<E>],
    proofs: &[VRFProofBatchable<E,PD>],
    public_keys: &[PublicKey<E>],
) -> SignatureResult<()> 
{
    const ASSERT_MESSAGE: &'static str = "The number of messages/transcripts / input points, output points, proofs, and public keys must be equal.";
    assert!(inouts.len() == proofs.len(), ASSERT_MESSAGE);
    assert!(proofs.len() == public_keys.len(), ASSERT_MESSAGE);

    // Use a random number generator keyed by the public keys, the
    // inout and output points, and the system randomn number gnerator.
    // TODO: Use proofs too?
    let mut csprng = {
        let mut t = Transcript::new(b"VB-RNG");
        for (pk,p) in public_keys.iter().zip(inouts) {
            t.commit_point(b"",&pk.0);
            p.commit(&mut t);
        }
        t.build_rng().finalize(&mut rand_hack())
    };

    // Select a random 128-bit scalar for each signature.
    // We may represent these as scalars because we use
    // variable time 256 bit multiplication below.
    let rnd_128bit_scalar = |_| {
        let mut r = [0u8; 16];
        csprng.fill_bytes(&mut r);
        let z: Scalar = crate::scalar::scalar_from_u128::<E>(r);
    };
    let zz: Vec<Scalar> = proofs.iter().map(rnd_128bit_scalar).collect();

    let z_s: Vec<Scalar> = zz.iter().zip(proofs)
        .map(|(z, proof)| z * proof.s)
        .collect();

    // Compute the basepoint coefficient, ∑ s[i] z[i] (mod l)
    let B_coefficient: Scalar = z_s.iter().sum();

    // TODO: Support extra messages and DLEQ proofs by handling this differently.
    let t0 = Transcript::new(b"VRF");
    let z_c: Vec<Scalar> = zz.iter().enumerate()
        .map( |(i, z)| z * proofs[i].shorten_dleq(t0.clone(), &public_keys[i], &ps[i]).c )
        .collect();

    // Compute (∑ z[i] s[i] (mod l)) B + ∑ (z[i] c[i] (mod l)) A[i] - ∑ z[i] R[i] = 0
    let mut b = RistrettoPoint::optional_multiscalar_mul(
        zz.iter().map(|z| -z)
            .chain(z_c.iter().cloned())
            .chain(once(B_coefficient)),
        proofs.iter().map(|proof| proof.R.decompress())
            .chain(public_keys.iter().map(|pk| Some(*pk.as_point())))
            .chain(once(Some(constants::RISTRETTO_BASEPOINT_POINT))),
    ).map(|id| id.is_identity()).unwrap_or(false);

    // Compute (∑ z[i] s[i] (mod l)) Input[i] + ∑ (z[i] c[i] (mod l)) Output[i] - ∑ z[i] Hr[i] = 0
    b &= RistrettoPoint::optional_multiscalar_mul(
        zz.iter().map(|z| -z)
            .chain(z_c)
            .chain(z_s),
        proofs.iter().map(|proof| proof.Hr.decompress())
            .chain(inouts.iter().map(|p| Some(*p.preoutput.as_point())))
            .chain(inouts.iter().map(|p| Some(*p.input.as_point()))),
    ).map(|id| id.is_identity()).unwrap_or(false);

    if b { Ok(()) } else {
        // Err(SignatureError::EquationFalse) 
        Err( signature_error("VRF signature validation failed") )
    }
}
*/

/*
/// Batch verify VRFs by different signers
///
///
#[cfg(any(feature = "alloc", feature = "std"))]
pub fn vrf_verify_batch(
    inouts: &[VRFInOut<E>],
    proofs: &[VRFProofBatchable<E,PD>],
    publickeys: &[PublicKey<E>],
) -> SignatureResult<()>
{
    let mut ts = transcripts.into_iter();
    let ps = ts.by_ref()
        .zip(publickeys)
        .zip(outs)
        .map(|((t, pk), out)| out.attach_input_hash(pk,t))
        .collect::<SignatureResult<Vec<VRFInOut<E>>>>() ?;
    assert!(ts.next().is_none(), "Too few VRF pre-outputs for VRF inputs.");
    assert!(
        ps.len() == outs.len(),
        "Too few VRF inputs for VRF pre-outputs."
    );
    if dleq_verify_batch(&ps[..], proofs, publickeys).is_ok() {
        Ok(ps.into_boxed_slice())
    } else {
        Err(SignatureError::EquationFalse)
    }
}
*/
