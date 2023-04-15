### Arkworks friendly transcripts for proofs using Fiat-Shamir

A simple wrapper around shake128 which provides transcript aka
tuple-hash style hashing for simple safe domain seperation, but
compatible with an `io::Write` interface for simple idomatic
integration into arkworks.

We do basic domain seperation using postfix writes of the lengths
of written data, as opposed to the prefix writes done by merlin, 
TupleHash from [SP 800-185](https://csrc.nist.gov/publications/detail/sp/800-185/final),
since postfix writes simplify polymorphic code.

### Why not merlin?

A trascript flavored hash like [merlin](https://merlin.cool/)
([docs](https://docs.rs/merlin/latest/merlin/)) simplifies protocol
development by somewhat abstracting away domain seperation.

Although merlin works fine in the dalek ecosystem, we discovered its
prefix length convention fits poorly with ecosystems like arkworks or
other zcash derivatives, which serialize and hash via the `io::Write`
trait or similar.

An `io::Write` instance should treat `h.write(xs);` exactly like
`for x in xs { h.write(x); }` so `write` cannot directly wrape
merlin's `append_bytes`.  In principle, one could still provide
merlin extension traits which serialize fully monomorphized arkworks
types into buffers, and then appends those to the merlin transcript.
Arkworks strives for polymorphism however, which while complex when
doing cryptography, brings many advantages.

Idiomatic rust should minimize allocations.  Also, zeroing secrets
appears easier or more natrual on the stack.  Those buffers should
thus live on the stack, not the heap.  Yet, rust still lacks dynamic
stack allocations ala alloca in C!

We know several hacky solutions of course, with diverse annoyances.
Yet, there is no good reason why a trascript style hasher should not
support `io::Write` natively, but doing this directly demands a
postfix length convention.

As a minor cost for us, any users whose hashing involves multiple
code paths should ensure they invoke label between arkworks types
and user data with possibly zero length.

Aside from postfix lengths..

There do exist people who feel STROBE maybe overkill, unfamiliar,
or not widely available.  Almost all sha3 implementations provide
shake128, making this transcript simple, portable, etc.

We also "correct" merlin's excessively opinionated requirement of
`&'static [u8]`s for labels, which complicates some key management
practices.
 
### Accumulation

We support accumulating hashed data in a `Vec<u8>`, which users could
then transport to a remote signer for actual signing or proving.
Although possible in principle, we do not reparse this accumulated data,
but regardless the accumulation should not break any domain seperation
that occurs inside the remore signer.

Ideally, accumulations should've applications specific labels both
prefixed inside the accumulations and postfixed by the remote signer.
A remote signer could check this prefix of course, but applying a
postfix label should suffice given we use Shake128.

We have a `debug-transcript` feature similar to merlin as well.
