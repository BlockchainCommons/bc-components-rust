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
bc-components = "0.11.0"
```

## Types

| Name | Description |
| --- | --- |
| AgreementPrivateKey | A Curve25519 private key used for X25519 key agreement. |
| AgreementPublicKey | A Curve25519 public key used for X25519 key agreement. |
| AuthenticationTag | The HMAC authentication tag produced by the encryption process. |
| ARID | An “Apparently Random Identifier” (ARID) |
| Compressed | A compressed binary object. |
| Digest | A cryptographically secure digest, implemented with SHA-256. |
| ECPrivateKey | An elliptic curve digital signature algorithm (ECDSA) private key. |
| ECPublicKey | A compressed elliptic curve digital signature algorithm (ECDSA) compressed public key. |
| ECUncompressedPublicKey | A compressed elliptic curve digital signature algorithm (ECDSA) uncompressed public key. |
| EncryptedMessage | A secure encrypted message. |
| Nonce | A random nonce (“number used once”). |
| PrivateKeyBase | Holds unique data from which keys for signing and encryption can be derived. |
| PublicKeyBase | Holds information used to communicate cryptographically with a remote entity. |
| SSKRGroupSpec | A specification for a group of shares within an SSKR split. |
| SSKRSecret | A secret to be split into shares. |
| SSKRShare | An SSKR share. Used with the functions `sskr_generate` and `sskr_combine`. |
| SSKRSpec | A specification for an SSKR split. |
| Salt | Random salt used to decorrelate other information. |
| SchnorrPublicKey | A Schnorr (x-only) elliptic curve public key. |
| SealedMessage | A sealed message can be sent to anyone, but only the intended recipient can decrypt it. |
| Signature | A cryptographic signature. Supports ECDSA and Schnorr. |
| SigningPublicKey | A public key that can be used for signing. Supports both ECDSA and |Schnorr. |
| SigningPrivateKey | A private ECDSA key for signing. |
| SymmetricKey | A symmetric encryption key. |
| URI | A URI. |
| UUID | A UUID. |

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

| Name              | Role                | Github                                            | Email                                 | GPG Fingerprint                                    |
| ----------------- | ------------------- | ------------------------------------------------- | ------------------------------------- | -------------------------------------------------- |
| Christopher Allen | Principal Architect | [@ChristopherA](https://github.com/ChristopherA)  | \<ChristopherA@LifeWithAlacrity.com\> | FDFE 14A5 4ECB 30FC 5D22  74EF F8D3 6C91 3574 05ED |
| Wolf McNally      | Lead Researcher/Engineer         | [@WolfMcNally](https://github.com/wolfmcnally)    | \<Wolf@WolfMcNally.com\>              | 9436 52EE 3844 1760 C3DC  3536 4B6C 2FCF 8947 80AE |

## Responsible Disclosure

We want to keep all of our software safe for everyone. If you have discovered a security vulnerability, we appreciate your help in disclosing it to us in a responsible manner. We are unfortunately not able to offer bug bounties at this time.

We do ask that you offer us good faith and use best efforts not to leak information or harm any user, their data, or our developer community. Please give us a reasonable amount of time to fix the issue before you publish it. Do not defraud our users or us in the process of discovery. We promise not to bring legal action against researchers who point out a problem provided they do their best to follow the these guidelines.

### Reporting a Vulnerability

Please report suspected security vulnerabilities in private via email to ChristopherA@BlockchainCommons.com (do not use this email for support). Please do NOT create publicly viewable issues for suspected security vulnerabilities.

The following keys may be used to communicate sensitive information to developers:

| Name              | Fingerprint                                        |
| ----------------- | -------------------------------------------------- |
| Christopher Allen | FDFE 14A5 4ECB 30FC 5D22  74EF F8D3 6C91 3574 05ED |

You can import a key by running the following command with that individual’s fingerprint: `gpg --recv-keys "<fingerprint>"` Ensure that you put quotes around fingerprints that contain spaces.
