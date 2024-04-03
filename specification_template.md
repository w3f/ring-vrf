# Bandersnatch VRFs

## VRF

{sections.vrf}

### VRF Key

{sections.vrf-keys}

## IETF VRF

Refer to [RFC-9381](https://www.rfc-editor.org/rfc/rfc9381) for the details.

### Bandersnatch Cipher Suite Configuration

Configuration follows the RFC-9381 suite specification guidelines.

* The EC group G is the Bandersnatch elliptic curve, in Twisted Edwards form,
  with the finite field and curve parameters as specified in the [neuromancer](https://neuromancer.sk/std/bls/Bandersnatch)
  standard curves database. For this group, `fLen` = `qLen` = 32 and `cofactor` = 4.

* The prime subgroup generator `g` is constructed following Zcash's guidelines:
  *"The generators of G1 and G2 are computed by finding the lexicographically
  smallest valid x-coordinate, and its lexicographically smallest y-coordinate
  and scaling it by the cofactor such that the result is not the point at infinity."*

  - g.x = `0x29c132cc2c0b34c5743711777bbe42f32b79c022ad998465e1e71866a252ae18`
  - g.y = `0x2a6c669eda123e0f157d8b50badcd586358cad81eee464605e3167b6cc974166`

* The public key generation primitive is `PK = SK · g`, with `SK` the secret
  key scalar and `g` the group generator. In this ciphersuite, the secret
  scalar `x` is equal to the secret key `SK`.

* `suite_string` = 0x33.

* `cLen` = 32.

* `encode_to_curve_salt` = `PK_string`.

* The `ECVRF_nonce_generation` function is as specified in Section 5.4.2.1 of RFC-9381.

* The `int_to_string` function encodes into the 32 bytes little endian representation.
 
* The `string_to_int` function decodes from the 32 bytes little endian representation.

* The point_to_string function converts a point on E to an octet
  string using compressed form. The Y coordinate is encoded using
  `int_to_string` function and the most significant bit of the last
  octet is used to keep track of the X's sign. This implies that
  the point is encoded on 32 bytes.

* The string_to_point function tries to decompress the point encoded
  according to `point_to_string` procedure. This function MUST outputs
  "INVALID" if the octet string does not decode to a point on the curve E.

* The hash function Hash is SHA-512 as specified in
  [RFC6234](https://www.rfc-editor.org/rfc/rfc6234), with hLen = 64.

* The ECVRF_encode_to_curve function is as specified in
  Section 5.4.1.2, with `h2c_suite_ID_string` = `"BANDERSNATCH_XMD:BLAKE2b_ELL2_RO_"`.
  The suite is defined in Section 8.5 of [RFC9380](https://datatracker.ietf.org/doc/rfc9380/).

## Pedersen VRF

Pedersen VRF resembles EC VRF but replaces the
public key by a Pedersen commitment to the secret key, which makes the
Pedersen VRF useful in anonymized ring VRFs, or perhaps group VRFs.

{sections.pedersen-vrf}

## VRF input

Procedure to map arbitrary user input to a point follows the `hash_to_curve`
procedure described by RFC9380.

    Suite_ID: "bandersnatch_XMD:SHA-512_ELL2_RO_"

See [ArkTranscript](TODO) for details.

### From transcript to point

You need to call challenge and add b"vrf-input" to it. getting random byte (some hash?)
then hash to curve it. 

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
