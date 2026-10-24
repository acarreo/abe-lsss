# Security Model

## Scope

The active ABE factory exposes the Waters ciphertext-policy (CP-ABE) and
GPSW key-policy (KP-ABE) constructions as CPA-secure schemes. The library
uses RELIC for pairing operations and OpenSSL/GMP for supporting operations.
This document describes intended use and current limits; it is not a proof of
security or an independent audit of the implementation.

As usual for pairing-based ABE, the scheme encapsulates a symmetric key, and
bulk data is protected under that key with a symmetric primitive (an AEAD such
as AES-GCM is available in the library). The CPA-secure ABE layer is therefore
the component that gates access; payload integrity is the job of the AEAD.

Chosen-ciphertext (CCA) variants are not enabled: the generic transform is
kept in the source but disabled, and the factory does not implement
multi-authority ABE, revocation, tracing, non-monotone policies, outsourced
decryption, or searchable encryption. Enum values and inherited interfaces do
not imply that these features are available.

## Assets and trust assumptions

- Plaintext, ABE private keys, authority master secrets, and any payload
  encryption keys derived or protected by the application are sensitive.
- An authority that holds a master secret is trusted to issue keys correctly.
  Compromise of that secret can undermine the attributes it controls.
- Assume attribute names, policy structure, key identifiers, and other
  serialized metadata may be visible. The implementation does not promise
  policy or attribute privacy.
- Select a RELIC curve and build configuration appropriate to the deployment.
  The default BLS12-381 setting is commonly estimated at roughly 128-bit
  classical security, but this is an approximate parameter-level estimate,
  not a guarantee for this fork or every supported RELIC configuration.

## Intended security properties

The implemented constructions are intended to provide ABE confidentiality
against an adversary whose attributes or access structure do not satisfy the
encryption condition, including resistance to collusion as defined by the
underlying constructions. The exposed schemes are CPA-secure; this repository
does not claim chosen-ciphertext security or formal equivalence between the
current code and a paper's proof. The code and parameter choices have not been
independently verified.

## Randomness

Key generation and encryption draw from the RELIC random source (the system
generator in the default build). `OpenABERNG` (`abe/zrng.h`) defines a minimal
random-byte interface with two implementations: `OpenABESystemRNG`, and
`OpenABEShakeRNG`, a deterministic SHAKE256-based expander whose output depends
only on its seed and personalization string. The deterministic generator is
not wired into the schemes; it is meant for constructions that must re-derive
randomness from a secret seed and must not be used for key generation.

## Out of scope and known limitations

- No independent cryptographic review or formal verification has been
  completed.
- Constant-time behavior is not guaranteed for the full codebase. Do not use
  this library where timing, cache, power, or other physical side channels are
  in scope without a separate evaluation.
- Secret zeroization is not guaranteed for all C++ objects, temporaries,
  allocator-managed memory, or serialized buffers.
- The full test suite runs leak-free under LeakSanitizer in CI.
- The global library lifecycle and serialization-compression setting are
  process-wide. Initialize before pairing operations, do not shut down while
  operations are active, and do not change compression during serialization
  or between serialization and deserialization of the same data.
- Deserialization and policy parsing have not been comprehensively fuzzed.
  Treat untrusted inputs as attacker-controlled and validate at the
  application boundary.
- RELIC, OpenSSL, GMP, compiler flags, selected curve, and build scripts are
  part of the trusted computing base. Their security properties are outside
  this project's independent validation.

See [SECURITY.md](../SECURITY.md) for responsible vulnerability reporting.
