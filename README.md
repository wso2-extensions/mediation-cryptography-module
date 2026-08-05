# WSO2 Integrator: MI — Cryptography Module

`mediation-cryptography-module` is a WSO2 Integrator: MI **module** that adds message-level
cryptography to mediation flows. It is designed to host **one component per cryptography family**;
the current release ships the **PGP (OpenPGP)** family, and further families (e.g. AES) can be added
to the same module without breaking existing flows.

The shared foundations are already in place for that growth:

- **Naming** — operations are family-prefixed (`pgp…`, and later `aes…`) so there are no collisions.
- **Connections** — key material is modeled as reusable, named **connections** resolved once and shared
  across mediation threads (see [Connections](#connections)).
- **Error codes** — a single `CRYPTO:` tag prefix with a reserved numeric block per family
  (see [Error codes](#error-codes)).

The cryptographic core is [Bouncy Castle](https://www.bouncycastle.org/), the same library every major
vendor's PGP feature is built on, so output is standard OpenPGP (RFC 9580 / RFC 4880) and interoperates
with GnuPG and any other compliant tool.

---

## PGP (OpenPGP)

The PGP family exposes six operations — four single operations and two combined operations — matching
the set offered by other integration vendors (MuleSoft Crypto, Boomi, webMethods, Apache Camel PGP).

Each operation transforms a payload: input comes from the **message body** (default) or an **expression**,
and the result is written to a **response variable** or, with `overwriteBody`, the message body. The
key material comes from a **connection**, not from the operation parameters. Its I/O mirrors the
**File connector / VFS** (text vs. binary), so it drops straight into a `File read → PGP → File write` chain.

### Operations

| Operation | Direction | Purpose |
|-----------|-----------|---------|
| `pgpEncrypt` | outbound | Encrypt data to a recipient's public key |
| `pgpDecrypt` | inbound | Decrypt data with your private key |
| `pgpSign` | outbound | Produce a one-pass signed message |
| `pgpVerify` | inbound | Verify a signed message and expose validity |
| `pgpSignAndEncrypt` | outbound | Sign **then** encrypt in a single pass |
| `pgpDecryptAndVerify` | inbound | Decrypt **then** verify in a single pass |

`pgpSignAndEncrypt` and `pgpDecryptAndVerify` are not the two single operations chained — they are built
with nested OpenPGP generators (encrypt-of-compress-of-one-pass-sign) so the output is a single standard
OpenPGP message that GnuPG and peer tools read natively.

---

## Connections

Key rings are **not** passed on each operation. Instead you create a **connection** that names a key
location; the connection is resolved and parsed **once** into an immutable Bouncy Castle key-ring
collection, held in memory, and shared read-only across mediation threads. Operations then reference a
connection **by name** through a config-key parameter.

There are two connection types:

| Connection type | Holds | Used by |
|-----------------|-------|---------|
| `PGP_PRIVATE_KEY` | your own secret key-ring + default passphrase (identity) | `pgpDecrypt`, `pgpSign`, and the private side of the combined ops |
| `PGP_PUBLIC_KEY` | external parties' public key-ring (trust store) | `pgpEncrypt`, `pgpVerify`, and the public side of the combined ops |

Keeping private and public material in **separate** connections lets each be rotated independently.

### Connection parameters (`init`)

| Parameter | Applies to | Description |
|-----------|-----------|-------------|
| `connectionType` | both | `PGP_PRIVATE_KEY` or `PGP_PUBLIC_KEY`. |
| `name` | both | Unique name the connection is referenced by. |
| `privateKeyPath` | private | Secret key-ring location (see [Key locations](#key-locations)). |
| `publicKeyPath` | public | Public key-ring location. |
| `keyIdentifier` | both | Key bound to this connection: a full fingerprint or a 16-hex 64-bit Key ID. See [Selecting a key](#selecting-a-key-from-the-ring). Required for encrypt/sign; optional for decrypt/verify. |
| `passphrase` | private | Passphrase protecting the secret key; supply via Secure Vault (see [Passphrase handling](#passphrase-handling-with-secure-vault)). |

### Key locations

A key location string is resolved by its prefix/shape, so the module works the same on a filesystem or
in a container:

| Form | Example | Notes |
|------|---------|-------|
| MI project resource | `resources:keys/partner.asc` | **Recommended.** Bundled with the integration project. |
| Environment variable | `env:PARTNER_PUBLIC_KEY` | The variable's value *is* the key material (e.g. injected from a Kubernetes Secret). |
| Inline ASCII-armored | `-----BEGIN PGP PUBLIC KEY BLOCK----- …` | The content itself is the key. |
| Filesystem path | `/opt/keys/partner.asc` | Legacy fallback. |
| Legacy registry | `gov:/…`, `conf:/…` | Governance / configuration registry. |

Both ASCII-armored and binary key material are accepted; the format is auto-detected.

---

## How data flows

Input and output are designed to chain with the File connector / VFS, which carry text as plain strings
and binary as base64:

- `inputSource` — where the input comes from: **`Message Body`** (default — the raw payload, read
  byte-faithfully) or **`Expression`** (read from `sourceContent`).
- `sourceContent` — used only when `inputSource` is `Expression`: an expression such as `${vars.x}` or
  `${payload.field}`.
-  `inputType` — how the input is carried on the **outbound** ops (encrypt / sign): `BINARY` (default)
   base64-decodes (the carriage `file.read` uses for a binary file); `TEXT` decodes via `charset`. This
  stays an explicit choice — for arbitrary plaintext, text-vs-base64 cannot be inferred safely. **Inbound**
  ops (decrypt / verify) auto-detect armored vs. binary, so there is no `inputType` to set.
- `responseVariable` — the result is assigned to this variable as an object with a `payload.output`
  field (base64 when the output is binary), plus `attributes`.
- `overwriteBody` — when `true`, the **raw** result becomes the message body with the right content type
  (`text/plain` or `application/octet-stream`) — ready for `file.write`.
- `outputType` (decrypt / verify ops) — `TEXT` or `BINARY`: how the recovered plaintext is represented.
  When omitted it **defaults from the OpenPGP literal-data format** recovered from the message (binary-tagged
  → `BINARY`, text-tagged → `TEXT`), so connector-to-connector exchanges round-trip automatically. For
  encrypt/sign the output's text/binary nature follows `armor` (armored → text, `armor=false` → binary).

`pgpVerify` and `pgpDecryptAndVerify` additionally include a **`signatureValid`** boolean in the result
variable's `attributes`, so you can branch with a `Filter` mediator (e.g. on
`${vars.<responseVariable>.attributes.signatureValid}`).

The decrypt/verify operations also surface any metadata embedded in the OpenPGP literal-data packet as
result-variable attributes — **`fileName`** (the original file name, when set) and **`modificationTime`**
(ISO-8601) — for example to name the file on a downstream `file.write`.

### Choosing `TEXT` vs `BINARY`

The value reflects the **nature of your plaintext**, not the OpenPGP form (armored vs. binary — that is
handled separately by `armor` on output and auto-detected on input). The rule of thumb: **use `TEXT` for
things a human would read as a string; use `BINARY` for raw file bytes.** When in doubt, `BINARY` is
lossless (base64 always round-trips); `TEXT` is more convenient but only correct for genuine text.

**`inputType`** — encrypt / sign / signAndEncrypt (how `sourceContent` / the body is carried *in*):

| Your input | Choose | What the module does |
|------------|--------|----------------------|
| Text — a string, JSON, XML, CSV; a text file read as `text/plain` | `TEXT` | takes the bytes from the string using `charset` |
| Binary — image, PDF, zip, any file read as `application/octet-stream` (so it arrives base64-encoded) | `BINARY` (default) | base64-decodes back to the original bytes |

**`outputType`** — decrypt / verify / decryptAndVerify (how the recovered plaintext is carried *out*):

| What you expect to recover | Choose | Result representation |
|----------------------------|--------|------------------------|
| Text — a readable string | `TEXT` | decoded to a String using `charset` |
| Binary — file bytes (image, PDF, zip, …) | `BINARY` | base64-encoded (safe for any bytes) |
| Not sure / connector-to-connector | *(omit)* | defaults from the sender's literal-data format tag |

`charset` applies only when the chosen type is `TEXT`; it is ignored for `BINARY`.

---

## Working with files (File connector / VFS)

The module never touches the filesystem itself; it transforms a payload. To process files, chain it with
the File connector or VFS: `file.read / VFS → cryptography.pgp* → file.write / VFS`.

OpenPGP data is either **armored** (ASCII text) or **binary**, and that form — not the file name — is what
matters:

| Form | Convention | Module setting |
|------|-----------|----------------|
| Armored (`-----BEGIN PGP …-----`) | `.asc` | `armor=true` / `inputType=TEXT` |
| Binary (raw OpenPGP bytes) | `.gpg`, `.pgp` | `armor=false` / `inputType=BINARY` |

- **File extensions are just a convention** — File/VFS read a file regardless of its extension, and OpenPGP
  mandates none. Use `.asc` for armored and `.gpg`/`.pgp` for binary so partners interpret it correctly.
- **Correct reading is governed by the content type, not the extension.** Read a binary `.pgp`/`.gpg` as
  `application/octet-stream` (+ `inputType=BINARY`); read an armored `.asc` as `text/plain`
  (+ `inputType=TEXT`). Reading binary as text corrupts it.
- **The module auto-detects armored vs. binary PGP on input**, so for decrypt/verify you only declare how
  the content is *carried*, not whether it was armored.
- **Match the output form to the file you'll write:** `armor=true` → text (`.asc`); `armor=false` → binary
  (`.gpg`/`.pgp`). With `overwriteBody=true` the result lands on the body with the right content type.

---

## Algorithm options

All algorithms are selectable by name; defaults are the modern interoperable choices.

**Symmetric (`symmetricKeyAlgorithm`)** — default `AES_256`

| Recommended | Legacy / interop-only |
|-------------|------------------------|
| `AES_256`, `AES_192`, `AES_128`, `TWOFISH`, `CAMELLIA_128`, `CAMELLIA_192`, `CAMELLIA_256` | `CAST5`, `TRIPLE_DES` (3DES), `BLOWFISH`, `IDEA` |

**Compression (`compressionAlgorithm`)** — default `ZLIB`

`ZLIB`, `ZIP` (most compatible), `BZIP2`, `UNCOMPRESSED`

**Signature hash (`signatureHashAlgorithm`)** — default `SHA256`

| Recommended | Legacy |
|-------------|--------|
| `SHA256`, `SHA384`, `SHA512` | `SHA224`, `SHA1`, `RIPEMD160` |

The public-key algorithm (RSA, ECDSA/EdDSA, ECDH) is determined by the key itself and needs no
configuration. Encryption uses the standard hybrid scheme: a one-time symmetric session key is generated
per message and wrapped with the recipient's public key. An integrity-protection (MDC) packet is added by
default (`integrityCheck = true`). On the inbound side, `requireIntegrity = true` (default) rejects a
decrypted message that carries no MDC packet at all; set it to `false` only to accept unprotected messages
from a legacy partner.

---

## Parameters by operation

Keys always come from a **connection** referenced by a config-key parameter; only algorithm and I/O
controls are set on the operation.

| Parameter | pgpEncrypt | pgpDecrypt | pgpSign | pgpVerify | pgpSignAndEncrypt | pgpDecryptAndVerify |
|-----------|:---:|:---:|:---:|:---:|:---:|:---:|
| `inputSource` / `sourceContent` / `charset` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `inputType` | ✓ | | ✓ | | ✓ | |
| `outputType` | | ✓ | | ✓ | | ✓ |
| `responseVariable` / `overwriteBody` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `encryptionConfigKey` (public conn.) | ✓ | | | | ✓ | |
| `decryptionConfigKey` (private conn.) | | ✓ | | | | ✓ |
| `signingConfigKey` (private conn.) | | | ✓ | | ✓ | |
| `verificationConfigKey` (public conn.) | | | | ✓ | | ✓ |
| `symmetricKeyAlgorithm` | ✓ | | | | ✓ | |
| `compressionAlgorithm` | ✓ | | ✓ | | ✓ | |
| `signatureHashAlgorithm` | | | ✓ | | ✓ | |
| `armor` | ✓ | | ✓ | | ✓ | |
| `integrityCheck` | ✓ | | | | ✓ | |
| `requireIntegrity` | | ✓ | | | | ✓ |
| `requireValidSignerKey` | | | | ✓ | | ✓ |
| `fileName` | ✓ | | ✓ | | ✓ | |

`requireValidSignerKey` (default `true`) rejects a cryptographically valid signature when the signer's key
was revoked or expired at signing time.

### Selecting a key from the ring

The key a connection uses is pinned by its **`keyIdentifier`**, auto-routed by shape (you do not choose the
kind):

1. **Fingerprint** — a full key fingerprint in hex (32/40/64 hex; `0x` prefix, spaces and colons are
   tolerated). The most precise and secure selector; recommended, and the modern OpenPGP (RFC 9580 / v6)
   practice.
2. **Key ID** — a 16-character (64-bit) hex Key ID, e.g. `0x7B9E1A2C3D4E5F6A`. Convenient but weaker than a
   fingerprint.
3. **User ID** — a user ID or e-mail, matched **exactly** and case-insensitively (a substring match is *not*
   done, to avoid collisions and key-spoofing).

For **encrypt / sign**, a `keyIdentifier` is **required**. A fingerprint or Key ID may point at a
certificate's primary key; if that key lacks the required capability (encryption is usually on a subkey),
the module falls back to the matching capability key in the same certificate. Revoked or expired keys are
never selected. **Decrypt / verify** need no identifier — the signer's key ID is read from the signature,
and decryption matches the message's recipient key IDs against your ring.

---

## Passphrase handling with Secure Vault

Private-key passphrases must **never** be hard-coded. Store them in the MI
[Secure Vault](https://mi.docs.wso2.com/en/latest/install-and-setup/setup/security/encrypting-passwords/)
and supply the resolved value as the connection's `passphrase`; the module receives the already-decrypted
value and never persists it.

---

## Usage example

### 1. Define the connections

Create the key-store connections once (the tooling writes them as connection local entries). A minimal
private-identity and public-trust pair:

```xml
<!-- Private identity (your key) -->
<cryptography.init>
    <connectionType>PGP_PRIVATE_KEY</connectionType>
    <name>MyIdentity</name>
    <privateKeyPath>resources:keys/our-private.asc</privateKeyPath>
    <keyIdentifier>0x7B9E1A2C3D4E5F6A</keyIdentifier>
    <passphrase>{wso2:vault-lookup('pgp.private.key.passphrase')}</passphrase>
</cryptography.init>

<!-- Public trust (partner key) -->
<cryptography.init>
    <connectionType>PGP_PUBLIC_KEY</connectionType>
    <name>PartnerTrust</name>
    <publicKeyPath>resources:keys/partner-public.asc</publicKeyPath>
    <keyIdentifier>partner@example.com</keyIdentifier>
</cryptography.init>
```

### 2. Inbound — decrypt then verify

```xml
<proxy name="SecureInboundProxy" transports="https" xmlns="http://ws.apache.org/ns/synapse">
  <target>
    <inSequence>
      <!-- the received .pgp content is the message body (e.g. from VFS or file.read) -->
      <cryptography.pgpDecryptAndVerify>
        <inputSource>Message Body</inputSource>
        <decryptionConfigKey>MyIdentity</decryptionConfigKey>
        <verificationConfigKey>PartnerTrust</verificationConfigKey>
        <requireIntegrity>true</requireIntegrity>
        <requireValidSignerKey>true</requireValidSignerKey>
        <responseVariable>pgpResult</responseVariable>
        <overwriteBody>false</overwriteBody>
      </cryptography.pgpDecryptAndVerify>

      <!-- branch on signature validity -->
      <filter xpath="${vars.pgpResult.attributes.signatureValid}">
        <then>
          <log category="INFO"><property name="msg" value="Signature valid, processing"/></log>
          <!-- ... continue mediation with ${vars.pgpResult.payload.output} ... -->
        </then>
        <else>
          <log category="WARN"><property name="msg" value="REJECTED: bad PGP signature"/></log>
          <drop/>
        </else>
      </filter>
    </inSequence>
  </target>
</proxy>
```

### 3. Outbound — sign then encrypt

```xml
<cryptography.pgpSignAndEncrypt>
  <inputSource>Expression</inputSource>
  <sourceContent>{${payload}}</sourceContent>
  <inputType>TEXT</inputType>
  <signingConfigKey>MyIdentity</signingConfigKey>
  <encryptionConfigKey>PartnerTrust</encryptionConfigKey>
  <symmetricKeyAlgorithm>AES_256</symmetricKeyAlgorithm>
  <compressionAlgorithm>ZLIB</compressionAlgorithm>
  <signatureHashAlgorithm>SHA256</signatureHashAlgorithm>
  <armor>true</armor>
  <responseVariable>pgpResult</responseVariable>
  <overwriteBody>true</overwriteBody>
</cryptography.pgpSignAndEncrypt>

<!-- overwriteBody=true => the message body is now the armored, signed-and-encrypted
     message (text/plain), ready to hand to file.write or a VFS endpoint.
     With overwriteBody=false it would instead be in ${vars.pgpResult.payload.output}. -->
```

---

## Build

```bash
mvn clean install
```

This produces `target/cryptography-module-1.0.0.zip`. External dependencies (Bouncy Castle) are declared in
`descriptor.yml` and resolved by the MI runtime — which already ships Bouncy Castle — so they are not
bundled inside the zip. Only the module's own jar is packaged under `lib/`.

## Deploy

Import `cryptography-module-1.0.0.zip` into your integration project (or drop it into
`MI-HOME/repository/deployment/server/synapse-libs` and enable it). Reference operations as
`cryptography.<operation>` from any sequence, proxy, or API.

---

## Error codes

On failure, an operation sets the synapse `ERROR_CODE` and `ERROR_MESSAGE` (and `ERROR_DETAIL` /
`ERROR_EXCEPTION`) on the message context and raises a fault, so a fault sequence can branch on the code.
Following the WSO2 connector convention, codes are six digits beginning with `7`; the `7013xx` block is
allocated to this module. Common codes share `701301`–`701319`; a per-family range follows (`701320`+ is
PGP-specific), and all share the single **`CRYPTO:`** tag prefix so future families remain consistent.

| Code | Tag | When it occurs |
|------|-----|----------------|
| `701301` | `CRYPTO:INVALID_INPUT` | Input missing, or not valid for the declared carriage (e.g. malformed base64). |
| `701302` | `CRYPTO:INVALID_CONFIGURATION` | Unsupported algorithm name, invalid `inputType`/`outputType`, or a bad selector (e.g. malformed fingerprint). |
| `701303` | `CRYPTO:KEY_NOT_FOUND` | Connection not deployed, key missing, no capability-matching key in the ring, or signer key not found. |
| `701304` | `CRYPTO:KEY_LOAD_ERROR` | A key-ring could not be read or parsed. |
| `701305` | `CRYPTO:INVALID_PASSPHRASE` | The private key could not be unlocked (wrong passphrase). |
| `701306` | `CRYPTO:INVALID_MESSAGE_FORMAT` | Input is not a valid OpenPGP message (not encrypted / not signed, or malformed). |
| `701307` | `CRYPTO:INTEGRITY_CHECK_FAILED` | MDC integrity verification failed — the message may have been tampered with. |
| `701308` | `CRYPTO:INTEGRITY_PROTECTION_MISSING` | The message carried no MDC packet and `requireIntegrity` is enabled. |
| `701309` | `CRYPTO:OPERATION_ERROR` | An encrypt / decrypt / sign / verify processing step failed. |
| `701310` | `CRYPTO:GENERAL_ERROR` | An unexpected error not covered by the codes above. |
| `701320` | `CRYPTO:KEY_UNUSABLE` | The selected key exists but is revoked or expired. |
| `701321` | `CRYPTO:SIGNER_KEY_UNTRUSTED` | Signature verified cryptographically, but the signer's key is revoked / expired and `requireValidSignerKey` is enabled. |

```xml
<!-- branch on a specific failure in a fault sequence -->
<filter source="$ctx:ERROR_CODE" regex="701307">
  <then>
    <log category="WARN"><property name="msg" value="REJECTED: tampered PGP message"/></log>
    <drop/>
  </then>
</filter>
```

---

## Standards & interoperability

The module emits and consumes standard OpenPGP messages (RFC 9580, the successor to RFC 4880).
Interoperability with **GnuPG 2.4** has been verified in both directions: GnuPG decrypts, verifies, and
decrypt-verifies module output; the module decrypts, verifies, and decrypt-verifies GnuPG output. Tamper
detection (modified ciphertext / broken signature) is rejected as invalid.

---

## Project layout

```
mediation-cryptography-module/
├── pom.xml
├── .connector-store/                               # Connector Store metadata (meta.json + icon.png)
└── src/main/
    ├── java/org/wso2/carbon/connector/cryptography/
    │   ├── exception/
    │   │   ├── CryptoError.java                     # 7013xx error codes / CRYPTO: tags
    │   │   └── CryptoException.java                 # cryptographic failure carrying a CryptoError
    │   └── pgp/
    │       ├── AbstractPGPOperation.java            # extends AbstractConnectorOperation; param/IO helpers
    │       ├── PGPEncrypt.java   PGPDecrypt.java
    │       ├── PGPSign.java      PGPVerify.java
    │       ├── PGPSignAndEncrypt.java   PGPDecryptAndVerify.java
    │       ├── connection/
    │       │   ├── PgpKeyStore.java                 # immutable, parsed private/public key store
    │       │   ├── PgpKeyStoreInit.java             # the connection 'init' operation
    │       │   └── PgpKeyStoreHandler.java          # process-wide registry of connections
    │       ├── constant/
    │       │   ├── PGPParameterKey.java             # operation & connection parameter names
    │       │   └── PGPCryptoConstants.java          # defaults, BC provider, name→algorithm mapping
    │       ├── model/
    │       │   ├── KeySelector.java                 # fingerprint / Key ID / user-ID selector
    │       │   ├── LiteralData.java                 # recovered payload + embedded metadata
    │       │   └── VerificationResult.java          # payload + signature-valid flag
    │       └── util/
    │           ├── KeySourceResolver.java           # resources:/env:/inline/file/registry → bytes
    │           ├── PGPKeyUtils.java                 # key-ring loading & key selection
    │           └── PGPCryptoUtils.java              # encrypt/decrypt/sign/verify/combined core
    ├── resources/
    │   ├── connector.xml                            # connector descriptor
    │   ├── descriptor.yml                           # declares external deps (Bouncy Castle)
    │   ├── icon/                                    # icon-small.png, icon-large.png
    │   ├── config/                                  # init.xml + invokeConnection.xml (connections)
    │   ├── pgp/                                     # component.xml + the 6 <operation>.xml templates
    │   ├── uischema/                                # low-code form per operation + per connection type
    │   └── outputschema/                            # output JSON schema per operation
    └── assembly/assemble-connector.xml              # builds the connector zip
```
