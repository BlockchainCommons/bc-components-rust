# Blockchain Commons Secure Components for Rust

<!--Guidelines: https://github.com/BlockchainCommons/secure-template/wiki -->

### _by Wolf McNally_

---

## Introduction

A collection of useful primitives for cryptography, semantic graphs, and
cryptocurrency, primarily for use in higher-level [Blockchain
Commons](https://blockchaincommons.com) projects like [Gordian
Envelope](https://crates.io/crates/bc-envelope). All the types are
[CBOR](https://cbor.io) serializable, and a number of them can also be
serialized to and from [URs](https://crates.io/crates/bc-ur).

Also includes a library of CBOR tags and UR types for use with these types.

## Getting Started

```toml
[dependencies]
bc-components = "0.20.0"
```

## Types

The library is organized into several categories of cryptographic primitives and utilities.

### Core Cryptographic Primitives

| Name             | Description                                                      |
| ---------------- | ---------------------------------------------------------------- |
| `Digest`         | A cryptographically secure digest, implemented with SHA-256      |
| `DigestProvider` | A trait for types that can provide cryptographic digests         |
| `Nonce`          | A random nonce ("number used once") for cryptographic operations |
| `Salt`           | Random salt used to decorrelate other information                |
| `Seed`           | Source of entropy for key generation with metadata               |

### Identifiers

| Name   | Description                                                    |
| ------ | -------------------------------------------------------------- |
| `ARID` | An "Apparently Random Identifier" using cryptographic hash     |
| `UUID` | A Universally Unique Identifier for resources                  |
| `XID`  | An eXtensible Identifier for extensible identification schemes |
| `URI`  | A Uniform Resource Identifier for web resources                |

### Symmetric Cryptography

| Name                | Description                                        |
| ------------------- | -------------------------------------------------- |
| `SymmetricKey`      | A symmetric encryption key for AES-256-GCM         |
| `AuthenticationTag` | The HMAC authentication tag produced by encryption |
| `EncryptedMessage`  | A secure authenticated encrypted message           |

### Elliptic Curve Cryptography

| Name                      | Description                                                     |
| ------------------------- | --------------------------------------------------------------- |
| `ECPrivateKey`            | An elliptic curve (secp256k1) private key for ECDSA and Schnorr |
| `ECPublicKey`             | A compressed elliptic curve public key                          |
| `ECUncompressedPublicKey` | An uncompressed elliptic curve public key                       |
| `SchnorrPublicKey`        | A Schnorr (x-only) elliptic curve public key (BIP-340)          |
| `Ed25519PrivateKey`       | An Edwards curve (Ed25519) private key for signatures           |
| `Ed25519PublicKey`        | An Edwards curve (Ed25519) public key                           |
| `X25519PrivateKey`        | A Curve25519 private key used for key agreement                 |
| `X25519PublicKey`         | A Curve25519 public key used for key agreement                  |

### Post-Quantum Cryptography

| Name              | Description                                                    |
| ----------------- | -------------------------------------------------------------- |
| `MLDSAPrivateKey` | A Module Lattice-based Digital Signature Algorithm private key |
| `MLDSAPublicKey`  | A Module Lattice-based Digital Signature Algorithm public key  |
| `MLDSASignature`  | A Module Lattice-based digital signature                       |
| `MLKEMPrivateKey` | A Module Lattice-based Key Encapsulation Mechanism private key |
| `MLKEMPublicKey`  | A Module Lattice-based Key Encapsulation Mechanism public key  |
| `MLKEMCiphertext` | Ciphertext produced by ML-KEM encapsulation                    |

### Digital Signatures

| Name                | Description                                                                   |
| ------------------- | ----------------------------------------------------------------------------- |
| `SigningPrivateKey` | A private key for digital signatures (Schnorr, ECDSA, Ed25519, MLDSA, or SSH) |
| `SigningPublicKey`  | A public key for signature verification                                       |
| `Signature`         | A digital signature supporting multiple algorithms                            |
| `SignatureScheme`   | Enumeration of supported signature schemes                                    |
| `Signer`            | A trait for types that can create signatures                                  |
| `Verifier`          | A trait for types that can verify signatures                                  |

### Key Encapsulation and Encryption

| Name                      | Description                                                       |
| ------------------------- | ----------------------------------------------------------------- |
| `EncapsulationPrivateKey` | A private key for key encapsulation (X25519 or ML-KEM)            |
| `EncapsulationPublicKey`  | A public key for key encapsulation                                |
| `EncapsulationCiphertext` | Ciphertext produced by key encapsulation                          |
| `SealedMessage`           | A message sealed for a specific recipient using key encapsulation |
| `EncapsulationScheme`     | Enumeration of supported key encapsulation schemes                |
| `Encrypter`               | A trait for types that can encrypt using public key               |
| `Decrypter`               | A trait for types that can decrypt using private key              |

### Secret Sharing

| Name            | Description                                                           |
| --------------- | --------------------------------------------------------------------- |
| `SSKRGroupSpec` | A specification for a group of shares within an SSKR split            |
| `SSKRSpec`      | A specification for an SSKR (Sharded Secret Key Reconstruction) split |
| `SSKRSecret`    | A secret to be split into shares                                      |
| `SSKRShare`     | An SSKR share used with `sskr_generate` and `sskr_combine` functions  |

### Key Management

| Name             | Description                                              |
| ---------------- | -------------------------------------------------------- |
| `PrivateKeyBase` | Holds unique data from which various keys can be derived |
| `PrivateKeys`    | Container for signing and encapsulation private keys     |
| `PublicKeys`     | Container for signing and encapsulation public keys      |
| `HKDFRng`        | A deterministic random number generator based on HKDF    |

### Utilities

| Name         | Description                                            |
| ------------ | ------------------------------------------------------ |
| `Compressed` | A compressed binary object with integrity verification |
| `Reference`  | A reference to a uniquely identified object            |

## Version History

- **0.5.0, September 14, 2024** - BREAKING CHANGE: Removed pre-hashing (tagged hash) support for Schnorr signatures, making them BIP-340 compliant. Schnorr signatures produced by previous versions of this crate will now only verify if you pre-hash the image yourself using the BIP-340 method and the tag you previously used, if any.

## Status - Community Review

`bc-components` is currently in a community review stage. We would appreciate your consideration and/or testing of the libraries. Obviously, let us know if you find any mistakes or problems. But also let us know if the API meets your needs, if the functionality is easy to use, if the usage of Rust feels properly standardized, and if the library solves any problems you are encountering when doing this kind of coding. Also let us know how it could be improved and what else you'd need for this to be just right for your usage. Comments can be posted [to the Gordian Developer Community](https://github.com/BlockchainCommons/Gordian-Developer-Community/discussions/116).

Because this library is still in a community review stage, it should not be used for production tasks until it has had further testing and auditing.

See [Blockchain Commons' Development Phases](https://github.com/BlockchainCommons/Community/blob/master/release-path.md).

## Financial Support

`bc-components` is a project of [Blockchain Commons](https://www.blockchaincommons.com/). We are proudly a "not-for-profit" social benefit corporation committed to open source & open development. Our work is funded entirely by donations and collaborative partnerships with people like you. Every contribution will be spent on building open tools, technologies, and techniques that sustain and advance blockchain and internet security infrastructure and promote an open web.

To financially support further development of `bc-components` and other projects, please consider becoming a Patron of Blockchain Commons through ongoing monthly patronage as a [GitHub Sponsor](https://github.com/sponsors/BlockchainCommons). You can also support Blockchain Commons with bitcoins at our [BTCPay Server](https://btcpay.blockchaincommons.com/).

## Contributing

We encourage public contributions through issues and pull requests! Please review [CONTRIBUTING.md](./CONTRIBUTING.md) for details on our development process. All contributions to this repository require a GPG signed [Contributor License Agreement](./CLA.md).

### Discussions

The best place to talk about Blockchain Commons and its projects is in our GitHub Discussions areas.

[**Gordian Developer Community**](https://github.com/BlockchainCommons/Gordian-Developer-Community/discussions). For standards and open-source developers who want to talk about interoperable wallet specifications, please use the Discussions area of the [Gordian Developer Community repo](https://github.com/BlockchainCommons/Gordian-Developer-Community/discussions). This is where you talk about Gordian specifications such as [Gordian Envelope](https://github.com/BlockchainCommons/Gordian/tree/master/Envelope#articles), [bc-shamir](https://github.com/BlockchainCommons/bc-shamir), [Sharded Secret Key Reconstruction](https://github.com/BlockchainCommons/bc-sskr), and [bc-ur](https://github.com/BlockchainCommons/bc-ur) as well as the larger [Gordian Architecture](https://github.com/BlockchainCommons/Gordian/blob/master/Docs/Overview-Architecture.md), its [Principles](https://github.com/BlockchainCommons/Gordian#gordian-principles) of independence, privacy, resilience, and openness, and its macro-architectural ideas such as functional partition (including airgapping, the original name of this community).

[**Gordian User Community**](https://github.com/BlockchainCommons/Gordian/discussions). For users of the Gordian reference apps, including [Gordian Coordinator](https://github.com/BlockchainCommons/iOS-GordianCoordinator), [Gordian Seed Tool](https://github.com/BlockchainCommons/GordianSeedTool-iOS), [Gordian Server](https://github.com/BlockchainCommons/GordianServer-macOS), [Gordian Wallet](https://github.com/BlockchainCommons/GordianWallet-iOS), and [SpotBit](https://github.com/BlockchainCommons/spotbit) as well as our whole series of [CLI apps](https://github.com/BlockchainCommons/Gordian/blob/master/Docs/Overview-Apps.md#cli-apps). This is a place to talk about bug reports and feature requests as well as to explore how our reference apps embody the [Gordian Principles](https://github.com/BlockchainCommons/Gordian#gordian-principles).

[**Blockchain Commons Discussions**](https://github.com/BlockchainCommons/Community/discussions). For developers, interns, and patrons of Blockchain Commons, please use the discussions area of the [Community repo](https://github.com/BlockchainCommons/Community) to talk about general Blockchain Commons issues, the intern program, or topics other than those covered by the [Gordian Developer Community](https://github.com/BlockchainCommons/Gordian-Developer-Community/discussions) or the
[Gordian User Community](https://github.com/BlockchainCommons/Gordian/discussions).

### Other Questions & Problems

As an open-source, open-development community, Blockchain Commons does not have the resources to provide direct support of our projects. Please consider the discussions area as a locale where you might get answers to questions. Alternatively, please use this repository's [issues](./issues) feature. Unfortunately, we can not make any promises on response time.

If your company requires support to use our projects, please feel free to contact us directly about options. We may be able to offer you a contract for support from one of our contributors, or we might be able to point you to another entity who can offer the contractual support that you need.

### Credits

The following people directly contributed to this repository. You can add your name here by getting involved. The first step is learning how to contribute from our [CONTRIBUTING.md](./CONTRIBUTING.md) documentation.

| Name              | Role                     | Github                                           | Email                                 | GPG Fingerprint                                   |
| ----------------- | ------------------------ | ------------------------------------------------ | ------------------------------------- | ------------------------------------------------- |
| Christopher Allen | Principal Architect      | [@ChristopherA](https://github.com/ChristopherA) | \<ChristopherA@LifeWithAlacrity.com\> | FDFE 14A5 4ECB 30FC 5D22 74EF F8D3 6C91 3574 05ED |
| Wolf McNally      | Lead Researcher/Engineer | [@WolfMcNally](https://github.com/wolfmcnally)   | \<Wolf@WolfMcNally.com\>              | 9436 52EE 3844 1760 C3DC 3536 4B6C 2FCF 8947 80AE |

## Responsible Disclosure

We want to keep all of our software safe for everyone. If you have discovered a security vulnerability, we appreciate your help in disclosing it to us in a responsible manner. We are unfortunately not able to offer bug bounties at this time.

We do ask that you offer us good faith and use best efforts not to leak information or harm any user, their data, or our developer community. Please give us a reasonable amount of time to fix the issue before you publish it. Do not defraud our users or us in the process of discovery. We promise not to bring legal action against researchers who point out a problem provided they do their best to follow the these guidelines.

### Reporting a Vulnerability

Please report suspected security vulnerabilities in private via email to ChristopherA@BlockchainCommons.com (do not use this email for support). Please do NOT create publicly viewable issues for suspected security vulnerabilities.

The following keys may be used to communicate sensitive information to developers:

| Name              | Fingerprint                                       |
| ----------------- | ------------------------------------------------- |
| Christopher Allen | FDFE 14A5 4ECB 30FC 5D22 74EF F8D3 6C91 3574 05ED |

You can import a key by running the following command with that individual's fingerprint: `gpg --recv-keys "<fingerprint>"` Ensure that you put quotes around fingerprints that contain spaces.
