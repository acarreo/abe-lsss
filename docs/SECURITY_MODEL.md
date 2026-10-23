# Security Model

## Scope

The active ABE factory exposes the Waters ciphertext-policy (CP-ABE) and
GPSW key-policy (KP-ABE) constructions through CPA interfaces. The library
uses RELIC for pairing operations and OpenSSL/GMP for supporting operations.
This document describes intended use and current limits; it is not a proof of
security or an independent audit of the implementation.

CCA ABE contexts are disabled, and the active factory does not implement
multi-authority ABE, revocation, tracing, non-monotone policies, outsourced
decryption, or searchable encryption. Enum values and inherited interfaces
do not imply that these features are available.

The CPA contexts do not authenticate ciphertexts: the payload is masked with a
hash-derived key stream, so a modified ciphertext can decrypt to different data
without an error (malleability). Applications that need integrity must
authenticate the payload themselves, for example with an AEAD under a key
protected by ABE.

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
underlying constructions. The exposed interface is CPA-secure only; this
repository does not claim chosen-ciphertext security, authenticated
ciphertexts, or formal equivalence between the current code and a paper's
proof. The code and parameter choices have not been independently verified.

Applications should authenticate data and handle tampering at an appropriate
layer. Do not treat successful parsing or an ABE decryption return code as
proof that attacker-controlled serialized data is authentic.

## Out of scope and known limitations

- No independent cryptographic review or formal verification has been
  completed.
- Constant-time behavior is not guaranteed for the full codebase. Do not use
  this library where timing, cache, power, or other physical side channels are
  in scope without a separate evaluation.
- Secret zeroization is not guaranteed for all C++ objects, temporaries,
  allocator-managed memory, or serialized buffers.
- The legacy full test suite still reports LeakSanitizer findings outside the
  focused serialization and key-derivation ownership regressions covered by
  CI. Full-suite leak detection is therefore not yet a passing gate.
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
