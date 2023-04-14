# Nugget BLS

Implements the [nugget BLS](https://eprint.iacr.org/2022/1611) protocols
for more efficent aggregation and gossip.

At first blush, BLS signatures need public keys and signatures to live on
opposite sides of the pairing, so verifiers need either slow G2 operations
for either the hash-to-curve or else for combining public key. 

In nugget BLS, we demand public keys be a DLEQ proof between points on
each of G1 and G2. so then aggregation sums the public keys on G2, but
verifiers only sub the G1 public keys.  We now have two verification
equations, but they could easily be merged after two scalar multiplications
on G1, so verifiers need only the G2 subgroup check and point preperation.

In principle, one always checks single BLS signatures before creating
aggregate BLS signatures.  Individual BLS signatures already create DoS risks,
which we aleviate by individual nugget BLS' signatures being DLEQ proofs,
that employ only G1 arithmetic. 

