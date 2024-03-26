# Ring VRF

{sections.vrf}


### Preliminaries 


### VRF Key

{sections.vrf-keys}

### VRF input

VRF input is an ArkTranscript. See ArkTranscript

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

The length of each item should be less than 2^31.

The transcript can be created with an initial domain label.
The label bytes are written into the hasher as all the other items which
may follow.

On construction the Shake128 hasher state is initialized to hash the empty
octet-string TODO @davxy: DOUBLE CHECK THIS

### Pre-defined functions

Get octet string length

```
    length(data)

      Input:
        - data: user data
      Output:
        - data length as 32 bit integer
```

Big-endian encoding of 32-bit unsigned integers

```
    big_endian_bytes(length)

      Input:
        - length: 32-bit integer
      Output:
        - 4 bytes big endian encoding of length
```

Update the hasher state with some data

```
    update_hasher(hasher, data)    

      Input:
        - hasher: Shake128 hasher
        - data: user provided data
```

### Transcript update

Update the hasher state with user data.

```
    write_bytes(hasher, data) 

      Inputs:
        - hasher: shake128 hasher state
        - data: user data

      Steps:
        1. update_hasher(hasher, data)
```

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
