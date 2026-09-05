# From a Chinese Rings CrackMe to License-Validation Hardening: Reverse-Engineering Lessons and Defensive Design

> **Scope and intended use**
>
> The subject of this article is an explicitly designated CrackMe training sample. It is used only to understand weaknesses in local license validation and to improve software protection. It is not applicable to bypassing third-party software licenses, generating unauthorized registration codes, or evading access controls. This document does not provide a key generator, reusable bypass scripts, or procedures for real commercial software.

The sample is small: a PE32 GUI application built with MSVC 6.0, with few imports and no packer. It embeds Chinese Rings state constraints in a local registration-code check. As a reverse-engineering exercise, it is useful for practicing control-flow recovery, arithmetic-semantics validation, and dynamic verification. As a licensing-design case study, it demonstrates a more important principle: **when the issuance rules and the entire decision process reside in the client, a complex algorithm can raise analysis cost but cannot become an authorization boundary.**

| Item | Observation |
|---|---|
| File | Approximately 1.9 KB PE32 GUI training sample |
| Compiler | MSVC 6.0 |
| Protections | No packer, no integrity validation, no server involvement |
| Validation location | Local client |
| Research objective | Identify the risks of reversible validation and propose deployable alternatives |

---

## 1. Recovering the validation boundary from the entry point

The program entry point creates a dialog. The registration button reads a user name and a numeric string, then enters a validation routine. The entire decision of whether the application is licensed occurs in the same client process: there is no external trust anchor, server state, or independent integrity or signature validation.

The risk of this structure is not determined by how small the code is. The attack surface comes from a single authorization decision point:

1. how inputs are transformed into internal state;
2. which states are accepted as success;
3. whether success and failure branches can be replaced; and
4. whether the package can be modified while users still trust it.

Once a researcher can observe these boundaries statically or dynamically, the local decision mechanism can be understood. The defensive priority is to move both "who may issue authorization" and "who remains entitled to use the product" outside a location fully controlled by the endpoint user.

---

## 2. Three design weaknesses in the sample

### 2.1 The client fully determines the validation rule

The sample transforms a user name into a fixed-width internal value and uses that value to drive later numeric validation. Every constant, transformation, and final acceptance condition ships with the binary.

This means there is no secret held only by the issuer. Whether the transformation uses shifts, multiplication, a state machine, or puzzle rules, an analyst can recover the rule or directly alter the acceptance branch when the verifier makes the decision entirely offline in a client they control.

### 2.2 A Chinese Rings state machine is analyzable, not a cryptographic signature

The sample encodes the valid transition conditions for multiple state bits using comparisons and XOR operations. The state graph has explicit rules and a fixed terminal state, which makes it a good algorithmic puzzle but a poor authorization credential.

The common mistake is to make the rule more complicated. Complexity makes reading harder but does not create an issuance secret. A licensing system needs a trust source that cannot be extracted from the client, such as an issuer-held private key or online entitlement state, rather than a more obscure local algorithm.

### 2.3 A single success branch is an attractive modification target

The sample ultimately funnels all states into a success or failure message. Even without reconstructing every mathematical rule, a concentrated decision point is valuable for patch analysis and tampering.

Simple string encryption or obfuscation only delays string searches. An analyst can still observe the authorization result through control flow, UI behavior, exception handling, or dynamic debugging. String obfuscation must not be treated as the core of license protection.

---

## 3. A more robust licensing architecture

### 3.1 Keep issuance authority with the publisher

Offline licensing can use a license payload signed with the publisher's private key. The client embeds only the public key and uses it to verify the signature. The private key remains only in a controlled issuance system and must never ship in an installer, update package, or client log.

A license payload should normally include at least:

- a license identifier, product, and version or feature scope;
- the licensed person or organization;
- start and expiry times, plus a defined migration policy;
- optional device or tenant binding data;
- format and key versions for future rotation; and
- a signature generated with the publisher's private key.

Define a canonical encoding before implementation so that one semantic license cannot have multiple byte representations. The client must validate the signature, product scope, time window, and version compatibility rather than check only a predictable local sequence.

### 3.2 Use online entitlement checks for revocation and risk response

An offline signature can stop third parties from issuing valid licenses, but it cannot immediately revoke a leaked entitlement or reliably assess anomalous use. Products that need revocation, seat control, subscription state, or high-value feature protection should maintain the entitlement source of truth on a server and confirm it at an appropriate cadence.

Online design must balance availability and privacy:

- allow a short offline grace period so temporary network failures do not lock out legitimate users;
- collect only necessary device and usage data, with a clear notice;
- do not use volatile hardware properties as the only binding factor; provide a legitimate migration and recovery route; and
- make server responses short-lived and constrained to a recipient and expiry window to reduce replay value.

### 3.3 Protect client integrity and the release chain

Signed licenses answer "who may issue," but they do not by themselves prevent an attacker from changing the local validation logic. Application delivery must be protected as well:

- code-sign EXE files, DLLs, and installers, and secure the update channel;
- keep important entitlement decisions on both the client and server rather than allowing a local Boolean to unlock every high-value feature;
- record only the necessary security events for integrity anomalies, signature failures, and authorization failures, and provide a user-understandable recovery path; and
- use layered checks and version rotation to raise tampering cost and improve detection, not as a substitute for cryptography.

Windows code signing can verify that a file has not been altered since signing and can associate a release with its signing identity. It should be combined with secure updates and server-side entitlement design. [Microsoft: Code signing](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/use-code-signing-for-better-control-and-protection)

---

## 4. Mapping threats to controls

| Risk | Primary control | Remaining consideration |
|---|---|---|
| Local rules are recovered and credentials are self-issued | Publisher private-key signatures; client stores only the public key | Private-key custody, rotation, and issuance audits still matter |
| Licenses are copied or resold long-term | Server-side entitlements, expiry, and measured device or tenant binding | Do not sacrifice legitimate migration and privacy |
| The local success path is modified | Code signing, integrity detection, and server confirmation for key actions | Local anti-tampering can raise cost but cannot provide an absolute guarantee |
| Old licenses or responses are replayed | Short-lived credentials, audience constraints, revocation, and version policy | Offline use needs a documented grace period |
| An update package is replaced | Signature validation, protected update channels, and release audits | Validation failures should fail safely and expose a support path |

---

## 5. Validating a hardened design

Security validation should use self-owned test systems and test keys only. Never use production private keys or real customer licenses in a test suite. A useful test set includes:

1. Valid licenses: the correct subject, product, feature set, and time window are accepted.
2. Tampered licenses: modifying any field, signature, or encoding is rejected.
3. Expired and not-yet-valid licenses: verify time boundaries and reasonable clock-skew handling.
4. Wrong product or version: a license cannot be reused across products, environments, or authorization scopes.
5. Key rotation: new and old public keys and license formats behave according to the migration policy.
6. Network failure: online-check failure leads to the promised grace period, read-only mode, or recovery flow.
7. Privacy review: telemetry is minimized and does not upload unnecessary device information, file content, or user data.

Automated tests should use dedicated test-issuance keys kept separate from production systems. Give failure results clear messages that do not expose internal decision logic, and ensure support channels can help legitimate users migrate or recover access.

---

## 6. Conclusions from the training sample

The Chinese Rings mechanism in this CrackMe is useful for reverse-engineering practice: window procedures, data flow, and state transitions can be used to validate an understanding of the sample. It does not have the security properties a real licensing system requires:

- it has no issuer-held signing secret;
- the validation logic and acceptance condition are entirely on the client;
- it has no revocable, auditable entitlement state; and
- simple string encryption and algorithmic complexity cannot withstand logic recovery or local tampering.

Preventing similar algorithms from being cracked or used to build a key generator is therefore not a matter of adding more local puzzle logic. The essential measures are an issuance authority that cannot be copied from the client, a trustworthy release chain, server-side entitlement control where needed, and recovery mechanisms that respect both availability and privacy.

## References

- [Microsoft: Use code signing for added control and protection](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/use-code-signing-for-better-control-and-protection)
- [Microsoft: Time stamping Authenticode signatures](https://learn.microsoft.com/en-us/windows/win32/seccrypto/time-stamping-authenticode-signatures)
