# DLEQ VRF-AD

Implements the two relevant verifiable random functions (VRFs) with
associated data (VRF-ADs) which arise from Chaum-Pedersen DLEQ proofs,
polymorphic over Arkworks' elliptic curves.

Thin VRF aka `ThinVrf` provides a regular VRF similar but broadly superior
to ["EC VRF"](https://www.ietf.org/id/draft-irtf-cfrg-vrf-15.html).
Thin VRF support batch verification or half-aggregation exactly like
Schnorr signatures, but which ECVRF lacks.
In essence, thin VRF *is* a Schnorr signature with base point given by
a pseudo-random (Fiat-Shamir) linear combination of base points, while
EC VRF is two linked Schnorr signatures on distinct base points.
Thin VRF should be slightly faster than EC VRF, be similarly sized on
typical Edwards curves, but slightly larger on larger BLS12 curves.
As a rule, new applications should always prefer thin VRF over EC VRF.

Pedersen VRF aka `PedersenVRF` resembles EC VRF but replaces the
public key by a Pedersen commitment to the secret key, which makes the
Pedersen VRF useful in anonymized ring VRFs, or perhaps group VRFs.
We provide both batchable and nonbatchable forms of the Pedresen VRF.
We favor the batchable form because our blinding factors enlarge our
signatures anyways, making the batchable form less significant
proportionally than batchable forms of EV VRF.

As the Pedersen VRF needs two verification equations, we support
DLEQ proofs between two distinct curves provided both have the same
subgroup order.  Around this, we support omitting the blinding factors
for  cross curve DLEQ proofs, like proving public keys on G1 and G2
of a BLS12 curve have the same secret key.  


