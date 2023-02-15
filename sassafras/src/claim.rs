



pub struct Claim {
    idx: AttemptIdx,
    blockhash: [u8;32],
    rand_vrf_preputput: VrfPreOut,
    revealed_vrf_preouput: VrfPreOut,
    thin_vrf_signature: ThinVrfSignature,
    erased_signature: Option<[u8; 64]>,
}

impl SecreKey {
    pub fn rand_vrf_io(&self, attempt: &AttemptInfo) -> VrfInOut {
        pub sorting_epoch_rand_seed = ??? ;
        let input = ??? {
            ???
        }.rand_vrf_input();
        self.vrf_inout(input)
    }
        
    pub sign_claim(&self, ticket: &OnchainTicket, blockhash: [u8;32]) -> SassafrasResult<Claim> {
        let rand_io = self.rand_vrf_io(attmept);
        let revealed_io = self.revealed_vrf_io(attmept);

        let mut t = Transcript::new(b"SassafrasTicket");
        ticket.body.raw_commit(&mut t);
        t.append_message(b"BlockHash", &blockchash);
        let ios = [&revealed_io,&rand_vrf_io];
        thin_vrf_signature = THIN_VRF.verify_thin_vrf(&mut t,&ios,&self.thin_vrf_signature) ?;

        let ticket_secret: TicketSecret = ??? ;
        let sk = ed25519_zebra::SigningKey::from(ticket_secret.erased_secret);
        let mut msg = [0u8; 32];
        t.challenge(b"Prehashed for Ed25519", &mut msg);
        let erased_signature = sk.sign(msg);

        Ok( Claim {
            idx: ticket.idx,
            blockhash,
            rand_vrf_preputput: rand_io.vrf_preputput.clone(),
            revealed_vrf_preouput: revealed_io.vrf_preputput.clone(),
            thin_vrf_signature,
            erased_signature,
        } )
    }
}

impl Claim {
    let rand_vrf_io(&self) -> VrfInOut {
        pub sorting_epoch_rand_seed = ??? ;
        let input = ??? {
            ???
        }.rand_vrf_input();
        VrfInOut { input, preoutput: self.vrf_preout.clone(), }
    }

    let revealed_vrf_io(&self) -> VrfInOut {
        let input = AttemptInfo {
            idx: self.idx,
            ticketing_epoch_rand_seed: ???,
        }.revealed_vrf_input();
        VrfInOut { input, preoutput: self.revealed_vrf_preouput.clone(), }
    }

    pub fn verifiy(&self, ticket: &OnchainTicket) -> SassafrasResult<???> {
        if self.idx != ticket.body.idx { return(Err( ??? )); }

        let revealed_io = self.revealed_vrf_io();
        let rand_vrf_io = self.rand_vrf_io();

        let mut t = Transcript::new(b"SassafrasTicket");
        ticket.body.raw_commit(&mut t);
        // We've no raw_commit for Claims becuase everything
        // winds up covered elsewhere.
        t.append_message(b"BlockHash", &blockchash);
        THIN_VRF.verify_thin_vrf(&mut t,&[&revealed_io,&rand_vrf_io],&self.thin_vrf_signature) ?;

        // We prove ownership of the erased slot key only optionally
        // because non-ticketed slots have no erased key, and crashed
        // nodes lost all their erased key.  We return whether this
        // option was taken for possible usage in concensus or rewards.
        let claimed_erased = if Some(erased_signature) = self.erased_signature {
            let pk = ed25519_zebra::VerificationKey::try_from(&ticket.erased_public) ?;
            let mut msg = [0u8; 32];
            t.challenge(b"Prehashed for Ed25519", &mut msg);
            pk.verify(erased_signature,msg) ?;
            1
        } else { 0 }
     } 
}



