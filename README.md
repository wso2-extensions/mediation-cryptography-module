# WSO2 Micro Integrator — PGP Cryptography Module

`mi-cryptography-module` is a WSO2 Micro Integrator (MI) **module** that adds OpenPGP
message-level cryptography to mediation flows. It exposes six operations — four single
operations and two combined operations — matching the operation set offered by other
integration vendors (MuleSoft Crypto, Boomi, webMethods, Apache Camel PGP).

It is implemented purely as **message mediation**: there are no connections to configure.
Each operation transforms a payload — input comes from `sourceContent` (an expression such
as `${payload}` or `${vars.fileContent}`) and the result is written to a **response variable**
or, with `overwriteBody`, the message body. Its I/O mirrors the **File connector / VFS**
(text vs. binary via base64), so it drops straight into a `File read → PGP → File write` chain.
The cryptographic core is [Bouncy Castle](https://www.bouncycastle.org/),
the same library every major vendor's PGP feature is built on, so output is standard
OpenPGP (RFC 9580 / RFC 4880) and interoperates with GnuPG and any other compliant tool.

## Operations

Operation names are `pgp`-prefixed so future cryptography families (e.g. `aes…`) can be added
to the same module without name collisions.

| Operation | Direction | Purpose |
|-----------|-----------|---------|
| `pgpEncrypt` | outbound | Encrypt data to a recipient's public key |
| `pgpDecrypt` | inbound | Decrypt data with your private key |
| `pgpSign` | outbound | Produce a one-pass signed message |
| `pgpVerify` | inbound | Verify a signed message and expose validity |
| `pgpSignAndEncrypt` | outbound | Sign **then** encrypt in a single pass |
| `pgpDecryptAndVerify` | inbound | Decrypt **then** verify in a single pass |

`pgpSignAndEncrypt` and `pgpDecryptAndVerify` are not the two single operations chained — they
are built with nested OpenPGP generators (encrypt-of-compress-of-one-pass-sign) so the
output is a single standard OpenPGP message that GnuPG and peer tools read natively.

## How data flows

Input and output are designed to chain with the File connector / VFS, which carry text as
plain strings and binary as base64:

- `sourceContent` — the data to process, as an expression: `${payload}` (the message body) or
  `${vars.x}` (e.g. a variable produced by `file.read`). Default: `${payload}`.
- `inputType` — how the input is carried. **Outbound (encrypt/sign):** `TEXT` (default) decodes via
  `charset`; `BINARY` base64-decodes (the carriage `file.read` uses for a binary file). This stays an
  explicit choice — for arbitrary plaintext, text-vs-base64 cannot be inferred safely. **Inbound
  (decrypt/verify):** auto-detected (armored OpenPGP → text, otherwise base64), so there is normally
  no `inputType` to set; a `TEXT`/`BINARY` value still overrides if ever needed.
- `responseVariable` — the result is assigned to this variable as a JSON object with an
  `output` field (base64 when the output is binary).
- `overwriteBody` — when `true`, the **raw** result becomes the message body with the right
  content type (`text/plain` or `application/octet-stream`) — ready for `file.write`.
- `outputType` (decrypt/verify ops) — `TEXT` (default) or `BINARY`: how the recovered plaintext
  is represented. For encrypt/sign the output's text/binary nature follows `armor`
  (armored → text, `armor=false` → binary).

`pgpVerify` and `pgpDecryptAndVerify` additionally include a **`signatureValid`** boolean field in
the result variable, so you can branch with a `Filter` mediator
(e.g. on `${vars.<responseVariable>.payload.signatureValid}`).

The decrypt/verify operations also surface any metadata embedded in the OpenPGP literal-data
packet as result-variable attributes — **`fileName`** (the original file name, when set) and
**`modificationTime`** (ISO-8601) — for example to name the file on a downstream `file.write`.

### Choosing `TEXT` vs `BINARY`

The value reflects the **nature of your plaintext**, not the OpenPGP form (armored vs. binary —
that is handled separately by `armor` on output and auto-detected on input). The rule of thumb:
**use `TEXT` for things a human would read as a string; use `BINARY` for raw file bytes.** When in
doubt, `BINARY` is lossless (base64 always round-trips); `TEXT` is more convenient but only correct
for genuine text.

**`inputType`** — encrypt / sign / signAndEncrypt (how `sourceContent` is carried *in*):

| Your input | Choose | What the module does |
|------------|--------|----------------------|
| Text — a string, JSON, XML, CSV; a text file read as `text/plain` | `TEXT` (default) | takes the bytes from the string using `charset` |
| Binary — image, PDF, zip, any file read as `application/octet-stream` (so it arrives base64-encoded) | `BINARY` | base64-decodes back to the original bytes |

**`outputType`** — decrypt / verify / decryptAndVerify (how the recovered plaintext is carried *out*):

| What you expect to recover | Choose | Result representation |
|----------------------------|--------|------------------------|
| Text — a readable string (it was text before encryption/signing) | `TEXT` (default) | decoded to a String using `charset` |
| Binary — file bytes (image, PDF, zip, …) | `BINARY` | base64-encoded (safe for any bytes; decode it on the next step or `file.write`) |

`charset` applies only when the chosen type is `TEXT`; it is ignored for `BINARY`. Inbound operations
do **not** take an `inputType` — armored-vs-binary is auto-detected — and `outputType` cannot be
auto-detected because OpenPGP does not reliably record whether the plaintext was text or binary, so
it stays an explicit choice (defaulting to `TEXT`). Match it to the downstream step: a `file.write`
of a binary file wants `BINARY`.

## Working with files (File connector / VFS)

The module never touches the filesystem itself; it transforms a payload. To process files,
chain it with the File connector or VFS: `file.read / VFS → cryptography.pgp* → file.write / VFS`.

OpenPGP data is either **armored** (ASCII text) or **binary**, and that form — not the file
name — is what matters:

| Form | Convention | Module setting |
|------|-----------|----------------|
| Armored (`-----BEGIN PGP …-----`) | `.asc` | `armor=true` / `inputType=TEXT` |
| Binary (raw OpenPGP bytes) | `.gpg`, `.pgp` | `armor=false` / `inputType=BINARY` |

- **File extensions are just a convention you choose** — File/VFS read a file regardless of its
  extension, and OpenPGP mandates none. Use `.asc` for armored and `.gpg`/`.pgp` for binary so
  partners interpret it correctly, but it's your call.
- **Correct reading is governed by the content type, not the extension.** Read a binary
  `.pgp`/`.gpg` as `application/octet-stream` (+ `inputType=BINARY`) so the bytes are preserved;
  read an armored `.asc` as `text/plain` (+ `inputType=TEXT`). Reading binary as text corrupts it.
- **The module auto-detects armored vs. binary PGP on input** (Bouncy Castle), so for decrypt/verify
  you only declare how the content is *carried* (TEXT/BINARY), not whether it was armored.
- **Match the output form to the file you'll write:** `armor=true` → text (`.asc`); `armor=false`
  → binary (`.gpg`/`.pgp`). With `overwriteBody=true` the result lands on the body with the right
  content type, ready for `file.write`.

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

The public-key algorithm (RSA, ECDSA/EdDSA, ECDH) is determined by the key itself and
needs no configuration. Encryption uses the standard hybrid scheme: a one-time symmetric
session key is generated per message and wrapped with the recipient's public key. An
integrity-protection (MDC) packet is added by default (`integrityCheck = true`). On the inbound
side, `requireIntegrity = true` (default) rejects a decrypted message that carries no MDC packet
at all; set it to `false` only to accept unprotected messages from a legacy partner.

## Parameters by operation

Common output controls: `armor` (ASCII-armor, default `true`), `fileName` (optional name
embedded in the literal-data packet).

| Parameter | pgpEncrypt | pgpDecrypt | pgpSign | pgpVerify | pgpSignAndEncrypt | pgpDecryptAndVerify |
|-----------|:---:|:---:|:---:|:---:|:---:|:---:|
| `sourceContent` / `inputType` / `charset` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `responseVariable` / `overwriteBody` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `outputType` | | ✓ | | ✓ | | ✓ |
| `publicKeyPath` | ✓ | | | ✓ | ✓ | ✓ |
| `privateKeyPath` | | ✓ | ✓ | | ✓ | ✓ |
| `passphrase` | | ✓ | ✓ | | ✓ | ✓ |
| `fingerprint` / `keyId` / `userId` (recipient) | ✓ | | | | ✓ | |
| `signingFingerprint` / `signingKeyId` / `signingUserId` | | | ✓ | | ✓ | |
| `symmetricKeyAlgorithm` | ✓ | | | | ✓ | |
| `compressionAlgorithm` | ✓ | | ✓ | | ✓ | |
| `signatureHashAlgorithm` | | | ✓ | | ✓ | |
| `armor` | ✓ | | ✓ | | ✓ | |
| `integrityCheck` | ✓ | | | | ✓ | |
| `requireIntegrity` | | ✓ | | | | ✓ |

### Selecting a key from the ring

Each side (recipient / signer) can be selected three ways, tried in order of precedence:

1. **`fingerprint`** — full key fingerprint in hex (spaces, colons and a `0x` prefix are
   tolerated). The most precise and secure selector; recommended, and the modern OpenPGP
   (RFC 9580 / v6) practice.
2. **`keyId`** / **`signingKeyId`** — a 64-bit key ID in decimal or `0x`-hex. Convenient but
   weaker (short/long key IDs can collide or be forged), so prefer the fingerprint.
3. **`userId`** / **`signingUserId`** — a user ID or email; the first matching certificate is used.

When none is given, the module selects the **first key in the ring with the required
capability** (encryption for `pgpEncrypt`, signing for `pgpSign`). A fingerprint or key ID may
point at a certificate's primary key; if that key lacks the required capability (encryption is
usually on a subkey), the module falls back to the matching capability key in the same
certificate. (`pgpVerify` / `pgpDecryptAndVerify` need no selector — the signer's key ID is read
from the signature, and decryption matches the message's recipient key IDs against your ring.)

## Passphrase handling with Secure Vault

Private-key passphrases must **never** be hard-coded. Store them in the MI
[Secure Vault](https://mi.docs.wso2.com/en/latest/install-and-setup/setup/security/encrypting-passwords/)
and resolve them at the synapse layer; the module receives the already-decrypted value
and never persists it.

```xml
<!-- resolve from the secure vault, then hand the plain value to the operation -->
<property name="pgpPass"
          expression="wso2:vault-lookup('pgp.private.key.passphrase')"
          scope="default" type="STRING"/>
```

## Usage example — inbound: decrypt then verify

```xml
<proxy name="SecureInboundProxy" transports="https" xmlns="http://ws.apache.org/ns/synapse">
  <target>
    <inSequence>
      <!-- resolve passphrase from Secure Vault -->
      <property name="pgpPass"
                expression="wso2:vault-lookup('pgp.private.key.passphrase')"
                scope="default" type="STRING"/>

      <!-- the received .pgp content is the message body (e.g. from VFS or file.read) -->
      <cryptography.pgpDecryptAndVerify>
        <sourceContent>{${payload}}</sourceContent>
        <inputType>BINARY</inputType>
        <outputType>TEXT</outputType>
        <privateKeyPath>/opt/keys/our-private.asc</privateKeyPath>
        <publicKeyPath>/opt/keys/partner-public.asc</publicKeyPath>
        <passphrase>{$ctx:pgpPass}</passphrase>
        <responseVariable>pgpResult</responseVariable>
        <overwriteBody>false</overwriteBody>
      </cryptography.pgpDecryptAndVerify>

      <!-- branch on signature validity -->
      <filter xpath="${vars.pgpResult.payload.signatureValid}">
        <then>
          <property name="payload" expression="${vars.pgpResult.payload.output}" scope="default"/>
          <log category="INFO"><property name="msg" value="Signature valid, processing"/></log>
          <!-- ... continue mediation ... -->
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

## Usage example — outbound: sign then encrypt

```xml
<property name="pgpPass"
          expression="wso2:vault-lookup('pgp.private.key.passphrase')"
          scope="default" type="STRING"/>

<cryptography.pgpSignAndEncrypt>
  <sourceContent>{${payload}}</sourceContent>
  <inputType>TEXT</inputType>
  <publicKeyPath>/opt/keys/partner-public.asc</publicKeyPath>
  <privateKeyPath>/opt/keys/our-private.asc</privateKeyPath>
  <passphrase>{$ctx:pgpPass}</passphrase>
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

## Build

```bash
mvn clean install
```

This produces `target/cryptography-module-1.0.0.zip`. External dependencies (Bouncy Castle)
are declared in `descriptor.yml` and resolved by the MI runtime — which already ships
Bouncy Castle 1.84 — so they are no longer bundled inside the zip. Only the module's own
jar is packaged under `lib/`.

## Deploy

Import `cryptography-module-1.0.0.zip` into your integration project (or drop it into
`MI-HOME/repository/deployment/server/synapse-libs` and enable it). Reference operations
as `cryptography.<operation>` from any sequence, proxy, or API.

## Error codes

On failure, an operation sets the synapse `ERROR_CODE` and `ERROR_MESSAGE` (and `ERROR_DETAIL` /
`ERROR_EXCEPTION`) on the message context and raises a fault, so a fault sequence can branch on
the code. Following the WSO2 connector convention, codes are six digits beginning with `7`; the
`7013xx` block is allocated to this module and the last two digits identify the specific error.

| Code | Tag | When it occurs |
|------|-----|----------------|
| `701301` | `PGP:INVALID_INPUT` | Input missing, or not valid for the declared carriage (e.g. malformed base64). |
| `701302` | `PGP:INVALID_CONFIGURATION` | Unsupported algorithm name, invalid `inputType`/`outputType`, or a bad selector (e.g. malformed fingerprint). |
| `701303` | `PGP:KEY_NOT_FOUND` | Key file missing, no capability-matching key in the ring, or signer key not found. |
| `701304` | `PGP:KEY_LOAD_ERROR` | A key-ring file could not be read or parsed. |
| `701305` | `PGP:INVALID_PASSPHRASE` | The private key could not be unlocked (wrong passphrase). |
| `701306` | `PGP:INVALID_PGP_DATA` | Input is not a valid OpenPGP message (not encrypted / not signed, or malformed). |
| `701307` | `PGP:INTEGRITY_CHECK_FAILED` | MDC integrity verification failed — the message may have been tampered with. |
| `701308` | `PGP:INTEGRITY_PROTECTION_MISSING` | The message carried no MDC packet and `requireIntegrity` is enabled. |
| `701309` | `PGP:CRYPTO_OPERATION_ERROR` | An encrypt / decrypt / sign / verify processing step failed. |
| `701310` | `PGP:GENERAL_ERROR` | An unexpected error not covered by the codes above. |

```xml
<!-- branch on a specific failure in a fault sequence -->
<filter source="$ctx:ERROR_CODE" regex="701307">
  <then>
    <log category="WARN"><property name="msg" value="REJECTED: tampered PGP message"/></log>
    <drop/>
  </then>
</filter>
```

## Standards & interoperability

The module emits and consumes standard OpenPGP messages (RFC 9580, the successor to
RFC 4880). Interoperability with **GnuPG 2.4** has been verified in both directions:
GnuPG decrypts, verifies, and decrypt-verifies module output; the module decrypts,
verifies, and decrypt-verifies GnuPG output. Tamper detection (modified ciphertext /
broken signature) is rejected as invalid.

## Project layout

```
mi-cryptography-module/
├── pom.xml
├── .connector-store/                           # Connector Store metadata (meta.json + icon.png)
├── docs/                                        # per-operation documentation
└── src/main/
    ├── java/org/wso2/carbon/connector/cryptography/
    │   ├── exception/CryptoException.java       # module-level cryptographic failure
    │   └── pgp/
    │       ├── AbstractPGPOperation.java        # extends AbstractConnectorOperation; param/IO helpers
    │       ├── PGPEncrypt.java  PGPDecrypt.java
    │       ├── PGPSign.java     PGPVerify.java
    │       ├── PGPSignAndEncrypt.java  PGPDecryptAndVerify.java
    │       └── util/
    │           ├── ParameterKey.java            # operation template parameter names
    │           ├── PGPCryptoConstants.java      # defaults, BC provider, name→algorithm tag mapping
    │           ├── PGPKeyUtils.java             # key-ring loading & key selection
    │           └── PGPCryptoUtils.java          # encrypt/decrypt/sign/verify/combined core
    ├── resources/
    │   ├── connector.xml                        # connector descriptor (one dependency: pgp)
    │   ├── descriptor.yml                       # declares external deps (Bouncy Castle)
    │   ├── icon/                                # icon-small.png, icon-large.png
    │   ├── pgp/                                 # component.xml + the 6 <operation>.xml synapse templates
    │   ├── uischema/                            # low-code UI form per operation
    │   └── outputschema/                        # output JSON schema per operation
    └── assembly/assemble-connector.xml          # builds the connector zip
```
