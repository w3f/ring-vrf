


use merlin::Transcript;


const SASSAFRAS_MAX_ATTEMPTS: usize = ;



type Epoch = u64;

/// We take 128 bits for the ticket score so no two honest tickets
/// ever have the same score.  If two tickets do have the same score
/// then two validators have maliciously selected the same secret key
/// to give themselves runs in block production so they can manipulate
/// the randomness, so all but one should be excluded by the sorting.
type SCORE = u128;

const SASSAFRAS_ATTEMPT_THRESHOLD: SCORE = ??? :

/// Ticket score 
/// 
/// We sort tickets sorted sequentially by score, prefering exlcuding
/// both duplicate scores and middle scores. 
#[derive(Clone,Copy,PartialOrd,Ord,PartialEq,Eq)]
pub struct Score(SCORE);

impl Score {
    pub fn new(&io: VrfInOut) -> Score {
        Score(SCORE::from_le_bytes( io.vrf_output_bytes(b"SassafrasAttempt") ))
    }

    pub fn is_early_in_epoch(&self) -> bool {
        self.0 < SASSAFRAS_ATTEMPT_THRESHOLD/2
    }

    pub is is_late_in_epoch(&self) -> bool {
        self.0 > (SCORE::MAX - SASSAFRAS_ATTEMPT_THRESHOLD/2)
    }

    /// We retain only extremal scores and exclude the middle scores.
    pub fn is_valid(&self) -> bool {
        self.is_his_early_in_epochead() || self.is_late_in_epoch()
    }
}


#[derive(Clone,Copy)]
pub struct AttemptIdx {
    pub ticketing_epoch: Epoch,
    pub index: u16,
}

impl AttemptId {
    pub fn commit(&self, t: &mut Transcript) {
        t.append_message(b"Epoch", self.ticketing_epoch.to_le_bytes());
        t.append_message(b"Index", self.index.to_le_bytes());
    }

    pub fn is_now(&self, ticketing_epoch: Epoch) -> bool {
        self.epoch = ticketing_epoch && self.index < SASSAFRAS_MAX_ATTEMPTS
    }
}

#[derive(Clone)]
pub struct AttemptInfo {
    pub idx: AttemptIdx,
    pub ticketing_epoch_rand_seed: [u8; 32],
}

impl AttemptInfo {
    pub fn ticket_vrf_input(&self) -> VrfInput {
        let mut t = Transcript::new(b"SassafrasTicketVrf");
        self.idx.commit(&mut t);
        t.append_message(b"RandSeed", &ticketing_epoch_rand_seed);
        VrfInput::from_transcript(t)
    }

    pub fn revealed_vrf_input(&self) -> VrfInput {
        let mut t = Transcript::new(b"SassafrasRevealedVrf");
        self.slot.commit(&mut t);
        t.append_message(b"RandSeed", &ticketing_epoch_rand_seed);
        VrfInput::from_transcript(t)
    }
}

fn zebra_secret_to_public(secret: &[u8; 32]) -> [u8; 32] {
    ed25519_zebra::VerificationKeyBytes::from(
        ed25519_zebra::SigningKey::from( secret )
    ).into()
}

impl SecretKey {
    pub fn ticket_vrf_io(&self, attempt: &AttemptInfo) -> VrfInOut {
        self.vrf_inout( attempt.ticket_vrf_input() )
    }

    pub fn revealed_vrf_io(&self, attempt: &AttemptInfo) -> VrfInOut {
        self.vrf_inout( attempt.revealed_vrf_input() )
    }

    pub fn attempt_ticket(attempt: &AttemptInfo) -> Option<(TicketSecret,TicketWire)> {
        use RngCore;
        let mut rng = rand_core::OsRng;

        let ticket_io = self.ticket_vrf_io(attmept);
        if ! Score::new(&ticket_io).valid() { return None; }

        // We could save ourselves handling this extra VRF IO by using
        // system randomness here and storing `revealed_secret` in
        // `TicketSecret`, but then the revealed trick breaks whenever
        // the block producer crashes.  Ain't too important either way.
        let revealed_io = self.revealed_vrf_io(attmept);
        let revealed_secret = revealed_io.vrf_output_bytes::<[u8; 32]>(b"SassafrasRevealed");

        let mut erased_secret = [0u8; 32];
        rng.fill_bytes(&mut erased_secret);

        let AttemptInfo { idx, .. } = attempt;
        let body = Ticket {
            idx,
            ticket_vrf_preout: ticket_io.preoutput.clone(),
            erased_public: zebra_secret_to_public(&erased_secret),
            revealed_public: zebra_secret_to_public(&revealed_secret),
        }

        let mut t = Transcript::new(b"SassafrasTicket");
        body.raw_commit(&mut t);

        let ring_proof = ;
        ring_proof.commit(&mut t);
        let pedersen_vrf_signature = self.pedersen_vrf.sign_pedersen_vrf(&mut t,&[ticket_io],&mut rng);

        Some((
            TicketSecret { idx, erased_secret, },
            TicketWire { body, pedersen_vrf_signature, ring_proof, }
        ))
    }

    pub fn attempt_all(&self, ticketing_epoch: Epoch) -> (Vec<TicketSecret>,Vec<TicketWire>) {
        let ticketing_epoch_rand_seed = ??? ;

        let secrets = Vec::new();
        let wires = Vec::new();
        for index in 0..SASSAFRAS_MAX_ATTEMPTS {
            let idx = AttemptIdx { ticketing_epoch, index };
            if Some((s,w)) = self.attempt_ticket(& AttemptInfo { idx, ticketing_epoch_rand_seed }) {
                secrets.push(s);
                wires.push(w);
            }
        }
    }
}

pub struct TicketSecret {
    idx: AttemptIdx,
    erased_secret: [u8; 32],
}

/// Internal ticket body 
pub struct TicketBody {
    idx: AttemptIdx,
    /// 
    ticket_vrf_preout: VrfPreOut, // [u8; VRF_PREOUT_LENGTH]
    /// A 32 byte Ed25519 public key which gets erased when opening the ticket.
    erased_public: [u8; 32],  // ed25519_zebra::VerificationKeyBytes,
    /// A 32 byte Ed25519 public key which gets exposed when opening the ticket
    revealed_public: [u8; 32],  // ed25519_zebra::VerificationKeyBytes,
}

impl TicketBody {
    pub(crate) fn raw_commit(&self, t: &mut Transcript) {
        self.idx.commit(t);
        // t.append_message(b"PreOut", self.ticket_vrf_preout); is redundant to the io commitment 
        t.append_message(b"ErasedPublic", &self.erased_public);
        t.append_message(b"RevealedPublic", &self.revealed_public);
    }

    pub fn ticket_vrf_io(&self) -> VrfInOut {
        let input = AttemptInfo {
            idx: self.idx,
            ticketing_epoch_rand_seed: ???,
        }.ticket_vrf_input();
        VrfInOut { input, preoutput: self.ticket_vrf_preout.clone(), }
    }
}

/// On-chain record for verified ticket 
pub struct OnchainTicket {
    score: Score,
    body: TicketBody,
}

/// Gossipable ticket wire format, possibly unverified.
pub struct TicketWire {
    body: TicketBody,
    ///
    pedersen_vrf_signature: PedersenVrfSignature,
    ///
    ring_proof: ring_proof::???,
}

impl TicketWire {
    pub fn serialize(&self) ???;
    pub fn deserialize(data: &[u8]) -> SassafrasResult<OnchainTicket>;

    pub fn validate(&self, ticketing_epoch: Epoch) -> SassafrasResult<TicketRecord> {
        if ! self.body.idx.is_now(ticketing_epoch) { return Err(???); }

        let ticket_io = self.body.ticket_vrf_io();
        let score = Score::new(&ticket_io);
        if ! score.valid() { return Err( ??? ); }

        let mut t = Transcript::new(b"SassafrasTicket");
        self.body.raw_commit(&mut t);
        ring_proof.commit(&mut t);
        PEDERSEN_VRF.verify_pedersen_vrf(&mut t,&[ticket_io],&self.pedersen_vrf_signature) ?;

        self.ring_proof.validate( ??? ) ?;

        Ok(OnchainTicket { score, body: self.body.clone() })
    }
}
