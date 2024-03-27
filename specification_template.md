# Ring VRF

{sections.vrf}


### Preliminaries 


### VRF Key

{sections.vrf-keys}

### VRF input

Procedure to map arbitrary user input to a point follows the `hash_to_curve`
procedure described by RFC9380.

    Suite_ID: "bandersnatch_XMD:SHA-512_ELL2_RO_"

See [ArkTranscript](TODO) for details.

#### From transcript to point

You need to call challenge and add b"vrf-input" to it. getting random byte (some hash?)
then hash to curve it. 

## DELQ VRF

### Preliminaries

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

{sections.dleq-vrf-preliminaries}

### Thin VRF

### Pedersen VRF

{sections.pedersen-vrf}

## Bandersnatch VRF

## Transcript

A Shake-128 based transcript construction which implements the Fiat-Shamir
transform procedure.

We do basic domain separation using postfix writes of the lengths of written
data (as opposed to the prefix writes by [Merlin](https://merlin.cool)
`TupleHash` from [SP 800-185](https://csrc.nist.gov/pubs/sp/800/185/final)).

    H(item_1, item_2, ..., item_n)

Represents the application of shake-128 to the concatenation of the serialization of each item
followed by the serialization of the length of each objects, as a 32-bit unsigned integer.

    bytes = encode(item_1) || encode(length(item_1)) || .. || encode(item_n) || encode(length(item_n))
    Shake128(bytes)

The length of each item should be less than 2^31.

## Objects Serialization Encoding

### Unsigned Integers

Unsigned integers are encoded in big-endian.

This applies to both fixed or arbitrary width unsigned integers.

TODO:
- ARK serializes integers in LE :-/
- Check Zcash serialization format (IIRC BE)

### EC Points

Elliptic curve points are serialized in compressed form as specified by TODO.

TODO isn't there any standard like https://www.secg.org/sec1-v2.pdf ?
There the standard serializes in BE as well.

TODO maybe we must convert to BE our serialized points/scalars?


## OBSOLETE (TODO: REMOVE THIS PARAGRAPH)

Write unlabeled domain separator into the hasher state.

```
    write_separator(hasher, data)

      Inputs:
        - hasher: shake128 hasher state
        - data: user data

      Steps:
        1. bytes = big_endian_bytes(length(data))
        2. write_bytes(hasher, bytes)
```

Update the hasher state with user provided data with separator.

```
    update(hasher, data)

      Inputs:
        - hasher: shake128 hasher state
        - data: user data

      Steps:
        1. write_bytes(hasher, data)
        2. write_separator(hasher, data)
```

### Challenge

Creates a challenge reader

```
    challenge(hasher, label)

      Inputs:
        - label: user provided domain separator (octet-string)
      Outputs:
        - Shake128 hash reader
    
      Steps:
        1. update(hasher, label)
        2. write_bytes(hasher, b"challenge")
        3. reader = get_reader(hasher)
        4. separate(hasher, b"challenge")
        5. return reader
```

### Forking

Forks transcript to prepare a witness reader

```
    fork(hasher, label)

      Inputs:
        - hasher: shake128 state
        - label: user provided label (octets)
      Output:
        - forked hasher state

      Steps:
        1. hasher_clone = clone(hasher)
        2. update(hasher_clone, label)
        3. return hasher_clone
```

### Witness

Create a witness reader from a forked transcript

```
    witness(hasher, rng)  

      Inputs:
        - hasher: shake128 state
        - rng: random number generator
      Output
        - Shake128 hasher reader

      Steps:
        1. rand = read_bytes(rng, 32)
        2. write_bytes(hasher, rand)
        3. reader = get_reader(hasher)
        4. return reader
```
