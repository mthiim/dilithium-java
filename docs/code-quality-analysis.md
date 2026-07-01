# Code Smells in the Wild: Dilithium Java

## Phase 1: Project Understanding

### Architecture Overview

This repository is a compact Java 8 Maven library that implements CRYSTALS-Dilithium 3.1 and exposes it through two surfaces:

- Low-level static cryptographic operations in `net.thiim.dilithium.impl.Dilithium`.
- Standard Java Cryptography Architecture (JCA/JCE) adapters in `net.thiim.dilithium.provider`.

The implementation depends on Bouncy Castle for SHAKE128 and SHAKE256. The repository also includes JUnit tests and utilities for known-answer test generation and performance timing.

### Package Structure

```text
net.thiim.dilithium
|-- interfaces
|   |-- DilithiumParameterSpec: immutable parameter sets for levels 2, 3, and 5
|   |-- DilithiumPublicKey / DilithiumPrivateKey: key interfaces
|   |-- DilithiumKeySpec and subclasses: key reconstruction specs
|
|-- impl
|   |-- Dilithium: key generation, signing, verification, challenge and hint logic
|   |-- Poly / PolyVec: polynomial and vector arithmetic
|   |-- PackingUtils: public key, private key, signature packing/unpacking
|   |-- DilithiumPublicKeyImpl / DilithiumPrivateKeyImpl: key implementations
|   |-- Utils: SHAKE helpers, byte concatenation, clearing, signature length
|
|-- provider
|   |-- DilithiumProvider: registers JCA services
|   |-- DilithiumKeyPairGenerator: JCA key generation adapter
|   |-- DilithiumKeyFactory: JCA key reconstruction adapter
|   |-- DilithiumSignature: JCA signature adapter
```

### Entry Points

- JCA user entry point: `DilithiumProvider`, then `KeyPairGenerator`, `Signature`, and `KeyFactory` with algorithm name `"Dilithium"`.
- Low-level entry point: static methods in `Dilithium`: `generateKeyPair`, `sign`, and `verify`.
- Test/utility entry points: `BasicTests`, `PerfTest`, `Timings`, and `KAT`.

### Execution Flow

Key generation:

```text
DilithiumKeyPairGenerator.generateKeyPair
-> random seed
-> Dilithium.generateKeyPair
-> expand seed into rho/rhoprime/K
-> sample s1 and s2
-> expand matrix A
-> compute public vector t1/t0
-> pack public/private keys
-> return KeyPair
```

Signing:

```text
DilithiumSignature.engineSign
-> Dilithium.sign
-> compute mu from tr and message
-> derive deterministic rhoprime
-> rejection loop over sampled y
-> compute w, challenge c, z, hints
-> pack signature
```

Verification:

```text
DilithiumSignature.engineVerify
-> Dilithium.verify
-> unpack c, z, h from signature
-> validate signature structure and z norm
-> compute mu from encoded public key and message
-> recompute w1 using A, z, c, t1, h
-> compare recomputed challenge with signature challenge
```

### Inheritance and Interfaces

- `DilithiumPublicKey` extends `java.security.PublicKey`.
- `DilithiumPrivateKey` extends `java.security.PrivateKey`.
- `DilithiumPublicKeyImpl` and `DilithiumPrivateKeyImpl` implement those interfaces.
- `DilithiumProvider` extends `java.security.Provider`.
- `DilithiumSignature` extends `java.security.SignatureSpi`.
- `DilithiumKeyPairGenerator` extends `java.security.KeyPairGeneratorSpi`.
- `DilithiumKeyFactory` extends `java.security.KeyFactorySpi`.

## Phase 2: Code Quality Analysis

| Issue | Location | Why It Matters | Severity | Suggested Refactoring |
|---|---|---|---|---|
| Long, algorithm-dense signing method | `Dilithium.java`, class `Dilithium`, method `sign`, lines 94-180 | Mixes precomputation selection, hashing, rejection loop, challenge generation, norm checks, hints, and packing in one method. Hard to audit and modify safely. | High | Extract small private helpers for private-key precomputation, `mu`/`rhoprime` derivation, and rejection-loop body. |
| Long verification method | `Dilithium.java`, class `Dilithium`, method `verify`, lines 182-269 | Unpacks, validates, computes, and compares in one path. Signature parsing errors and cryptographic verification are interleaved. | High | Extract signature unpacking into a small result object and isolate structural validation. |
| Large `Poly` class | `Poly.java`, class `Poly`, lines 1-514 | Arithmetic, sampling, packing, unpack-adjacent logic, norm checks, and formatting are combined. This lowers cohesion. | High | Split packing-related behavior to packing helpers only after adding test coverage; keep arithmetic in `Poly`. |
| Large `PackingUtils` class | `PackingUtils.java`, class `PackingUtils`, lines 1-357 | Public key, private key, signature, eta, t0, t1, z, and w1 encoding are all mixed together. | High | Extract `KeyPacking` and `SignaturePacking` helpers, preserving package-private API at first. |
| Repeated gamma2 decomposition logic | `Dilithium.java` `useHint`, lines 299-332 and `Poly.java` `decompose`, lines 396-419 | Same parameter-dependent arithmetic appears in multiple places, increasing risk of inconsistent future fixes. | Medium | Extract shared package-private helper for high/low bits if tests cover all parameter sets. |
| Repeated gamma1 z-pack/unpack logic | `Poly.java` `zpack`, lines 467-506 and `PackingUtils.java` `zunpack`, lines 318-356 | Bit layout is duplicated in inverse forms with high cognitive load. | Medium | Add focused round-trip tests, then introduce named constants and helper methods for both gamma1 variants. |
| Public key/private key internals expose mutable arrays | `DilithiumPublicKeyImpl.java`, `DilithiumPrivateKeyImpl.java`, getters and constructors | Callers can mutate encoded keys or internal seeds after construction, weakening encapsulation. | Medium | Consider defensive copies for public encoded arrays; for cryptographic internals, assess compatibility/performance before changing. |
| Key spec exposes mutable byte arrays | `DilithiumKeySpec.java`, methods `getBytes` and constructor, lines 6-17 | Caller mutations can change key reconstruction inputs after object construction. | Medium | Clone arrays on input/output. This is behaviorally safer but should be tested for compatibility. |
| JCA adapter threw undeclared unchecked exceptions | `DilithiumSignature.java`, old lines 29 and 40; `DilithiumKeyFactory.java`, old lines 19 and 28 | JCA callers expect `InvalidKeyException` or `InvalidKeySpecException`, not `IllegalArgumentException`. | Medium | Use the checked exceptions declared by SPI methods. Implemented in this refactoring. |
| Duplicate message-buffer reset logic | `DilithiumSignature.java`, old lines 34, 45, 65, and 76 | Small DRY violation; future state reset changes would require multiple edits. | Low | Extract `resetMessageBuffer()`. Implemented in this refactoring. |
| Generic unchecked exceptions for malformed signatures | `Dilithium.java`, method `verify`, lines 187, 209, 214, 224, 229 | Mixed `RuntimeException` and `IllegalArgumentException` make caller handling inconsistent. | Medium | Introduce a package-specific unchecked exception or consistently use `IllegalArgumentException`; coordinate with JCA wrapper behavior. |
| Magic numbers in packing and sampling | `Poly.java`, `PackingUtils.java`, multiple methods | Constants like 576, 640, 96, 128, 0x3FFFF, 0xFFFFF encode specification rules without names. | Medium | Replace with named constants only where they document layout without changing math. |
| `Utils.concat` catches impossible `IOException` from `ByteArrayOutputStream` | `Utils.java`, method `concat`, lines 18-28 | Adds noise and hides context with a generic runtime exception. | Low | Use `ByteArrayOutputStream.write(byte[], int, int)` or pre-sized byte array copy. |
| Deprecated provider construction style | `DilithiumProvider.java`, constructor, lines 8-31 | Uses old `Provider` APIs and comments say key factories above signature registration. | Low | Replace with clearer service registration constants if Java target permits; fix comment wording. |

## Phase 3: Prioritization

| Issue | Severity | Estimated Effort | Risk | Recommended Fix |
|---|---:|---:|---:|---|
| `Dilithium.sign` complexity | High | Medium | Medium | Extract helpers around workflow boundaries only; do not change arithmetic. |
| `Dilithium.verify` complexity | High | Medium | Medium | Extract signature parsing/validation object. |
| `Poly` large class / mixed responsibilities | High | High | High | Refactor only after adding round-trip and KAT coverage. |
| `PackingUtils` large class | High | Medium | Medium | Split key and signature packing helpers incrementally. |
| Mutable key/key-spec arrays | Medium | Medium | Medium | Add defensive-copy tests, then clone arrays. |
| Exception contract mismatch in JCA layer | Medium | Low | Low | Completed. |
| Repeated gamma2/gamma1 branches | Medium | Medium | Medium | Introduce shared helpers with round-trip tests. |
| Magic numbers | Medium | Low | Low | Replace with named constants near packing methods. |
| Duplicate buffer resets | Low | Low | Low | Completed. |

## Phase 4: Refactoring Performed

### Refactoring 1: Use Correct JCA Exceptions

Before:

```java
throw new IllegalArgumentException("Not a valid public key");
throw new IllegalArgumentException("Invalid key spec");
```

After:

```java
throw new InvalidKeyException("Not a valid public key");
throw new InvalidKeySpecException("Invalid public key spec");
```

Reason: the SPI method signatures already declare these checked exceptions, and JCA callers expect them. This improves API correctness without changing valid signing, verification, key generation, or serialization behavior.

### Refactoring 2: Extract Message Buffer Reset

Before:

```java
baos = new ByteArrayOutputStream();
```

repeated in initialization, signing, and verification.

After:

```java
private void resetMessageBuffer() {
    baos = new ByteArrayOutputStream();
}
```

Reason: the repeated state-reset operation now has one name and one implementation. The new helper allocates the same object at the same lifecycle points, so behavior remains unchanged.

## Phase 5: Functional Validation

Command:

```bash
mvn test
```

Result:

```text
Tests run: 4, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

Why behavior is unchanged:

- No arithmetic, bit packing, hashing, random sampling, challenge generation, or norm-checking code was modified.
- Valid keys and key specs still flow through the same casts and unpacking logic.
- The message buffer is reset at the same points as before; only the repeated allocation was extracted into a helper.
- Exception changes only affect invalid adapter input types.

## Phase 6: Pull Request Preparation

Branch name:

```bash
refactor/jca-adapter-quality
```

Suggested commands:

```bash
git checkout -b refactor/jca-adapter-quality
git add src/main/java/net/thiim/dilithium/provider/DilithiumSignature.java src/main/java/net/thiim/dilithium/provider/DilithiumKeyFactory.java docs/code-quality-analysis.md
git commit -m "Improve JCA adapter exception handling"
git commit -m "Document code quality analysis and refactoring plan"
```

PR title:

```text
Improve JCA adapter exception handling and document refactoring plan
```

PR summary:

```text
## Summary
- Align Dilithium JCA adapter error handling with the checked exceptions declared by the Java security SPI contracts.
- Extract repeated signature message-buffer reset logic into a helper.
- Add assignment-oriented code quality analysis and a prioritized refactoring plan.

## Problems Fixed
- Invalid key and key-spec inputs previously raised generic unchecked exceptions from SPI methods.
- Signature buffer reset logic was repeated in multiple places.

## Refactoring Techniques Used
- Replace inappropriate exception type.
- Extract method.
- Documentation of design smells and future refactoring sequence.

## Evidence Functionality Is Unchanged
- `mvn test` passes: 4 tests, 0 failures, 0 errors.
- Cryptographic implementation code in `Dilithium`, `Poly`, `PolyVec`, and `PackingUtils` was not changed.

## Benefits
- More predictable JCA behavior for invalid inputs.
- Slightly clearer state management in `DilithiumSignature`.
- A safer roadmap for future refactoring of cryptographic code.

## Future Work
- Add focused packing round-trip tests before refactoring `PackingUtils`.
- Extract signature parsing from `Dilithium.verify`.
- Consider defensive copies in key and key-spec classes.
```

## Phase 7: Assignment Report Content

### Repository Overview

`dilithium-java` is an educational Java implementation of CRYSTALS-Dilithium 3.1 with a JCA provider wrapper. It supports Dilithium security levels 2, 3, and 5, deterministic signatures, raw key serialization, and KAT generation.

### Architecture

The architecture is layered: JCA provider classes adapt Java security APIs to the low-level implementation; interfaces define keys and parameters; implementation classes perform arithmetic, packing, key generation, signing, and verification.

### Major Components

- `Dilithium`: core workflow coordinator.
- `Poly` and `PolyVec`: mathematical data structures and operations.
- `PackingUtils`: byte serialization/deserialization.
- `DilithiumSignature`, `DilithiumKeyPairGenerator`, `DilithiumKeyFactory`: JCA integration.
- `BasicTests`: functional behavior and serialization checks.

### Code Smells Found

The main smells are long methods, large classes, duplicated parameter-branch logic, magic numbers, mutable internal state exposure, generic exception handling, and low cohesion in packing/arithmetic classes.

### Tool-Based Analysis Suggestions

- SonarQube: method complexity, duplicate code, mutable exposure, exception correctness.
- PMD: excessive method length, cyclomatic complexity, data class warnings.
- Checkstyle: naming, formatting, missing braces, constant ordering.
- IntelliJ Inspections: access modifiers, deprecated APIs, redundant code, exception contract issues.

### Manual Analysis

Manual review is essential because much of the code mirrors reference cryptographic algorithms. Some apparent smells, such as bit-level packing and branch-heavy parameter handling, are partly inherent to the domain and should only be refactored with strong tests.

### Refactoring Decisions

The first implemented refactoring avoided cryptographic internals. It improved the JCA adapter layer, where behavior is easier to reason about and the risk to cryptographic correctness is low.

### Before vs After Comparison

Before, invalid JCA inputs produced generic unchecked exceptions and buffer reset code was repeated. After, invalid inputs use declared SPI exceptions and buffer reset is centralized in one helper.

### Functional Validation

The Maven test suite passed after the change. The existing tests cover key generation, sign/verify behavior across levels, serialization/reconstruction, and performance smoke execution.

### Challenges

The biggest challenge is separating ordinary maintainability concerns from cryptographic correctness risk. Some refactorings that look simple can affect exact byte output or timing behavior if done carelessly.

### Lessons Learned

For cryptographic code, the best first refactorings are around API boundaries, naming, validation, documentation, and tests. Core math should be changed only in tiny increments with strong regression evidence.

### Reflection

This project demonstrates that real-world maintainability work is not about cosmetic edits. The most valuable improvements are those that reduce future mistake probability while preserving behavior exactly.
