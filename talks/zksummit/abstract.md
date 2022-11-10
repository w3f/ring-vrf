Anonymized ring VRFs are ring signatures that prove correct evaluation of some authorized signer's PRF while hiding the specific signer's identity within some set of possible signers, known as the ring.  We propose ring VRFs as a natural fulcrum around which a diverse array of zkSNARK circuits turn, making them an ideal target for optimization and eventually standards. 

We show how rerandomizable Groth16 zkSNARKs transform into reusable zero-knowledge continuations, and build a ring VRF that amortizes expensive ring membership proofs across many ring VRF signatures. 
In  fact, our ring VRF needs only eight G_1 and two G_2 scalar multiplications, making it the only ring signature with performance competitive with constructions like group signatures.

Ring VRFs produce a unique identity for any give context but which remain unlinkable between different contexts.  These unlinkable but unique pseudonyms provide a far better balance between user privacy and service provider or social interests than attribute based credentials like IRMA.

Ring VRFs support anonymously rationing or rate limiting resource consumption that winds up vastly more efficient than purchases via monetary transactions. 



