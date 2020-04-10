The ideal cryptographic hash function has the following main properties:

- it is deterministic, meaning that the same message always results in the same hash.
- it is quick to compute the hash value for any given message.
- it is infeasible to generate a message that yields a given hash value.
- it is infeasible to find two different messages with the same hash value.
- a small change to a message should change the hash value so extensively that the new hash value appears uncorrelated with the old hash value (avalanche effect).

In theoretical cryptography, the security level of a cryptographic hash function has been defined using the following properties:

- Pre-image resistance: Given a hash value h it should be difficult to find any message m such that h = hash(m).
                        This concept is related to that of a one-way function.
                        Functions that lack this property are vulnerable to preimage attacks.

- Second pre-image resistance: Given an input m1, it should be difficult to find a different input m2 such that hash(m1) = hash(m2).
                               This property is sometimes referred to as weak collision resistance.
                               Functions that lack this property are vulnerable to second-preimage attacks.

- Collision resistance: It should be difficult to find two different messages m1 and m2 such that hash(m1) = hash(m2).
                        Such a pair is called a cryptographic hash collision.
                        This property is sometimes referred to as strong collision resistance.
                        It requires a hash value at least twice as long as that required for pre-image resistance; otherwise collisions may be found by a birthday attack.