/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.connector.cryptography.pgp.constant;

/**
 * Names of the operation template parameters exposed by the PGP operations.
 *
 * <p>These are the keys looked up from the synapse template parameters at
 * mediation time.</p>
 */
public final class PGPParameterKey {

    private PGPParameterKey() {
    }

    /**
     * Where the operation reads its input from: {@code "Message Body"} (default — the raw message
     * payload, read byte-faithfully) or {@code "Expression"} (read from {@link #SOURCE_CONTENT}).
     */
    public static final String INPUT_SOURCE = "inputSource";
    /** {@link #INPUT_SOURCE} value selecting the {@link #SOURCE_CONTENT} expression. */
    public static final String INPUT_SOURCE_EXPRESSION = "Expression";

    /**
     * The input expression, used only when {@link #INPUT_SOURCE} is {@code "Expression"}:
     * {@code ${vars.x}} (a variable) or {@code ${payload.field}} (a message field).
     */
    public static final String SOURCE_CONTENT = "sourceContent";
    /** How the input is represented: {@code TEXT} or {@code BINARY} (base64). */
    public static final String INPUT_TYPE = "inputType";
    /** How the operation output is represented: {@code TEXT} or {@code BINARY} (base64). */
    public static final String OUTPUT_TYPE = "outputType";
    /** Charset used for TEXT input/output. Default {@code UTF-8}. */
    public static final String CHARSET = "charset";

    /**
     * Public-key location. Supports multiple sources: a WSO2 Registry key ({@code gov:/...},
     * {@code conf:/...} or {@code resources:...}), an environment variable ({@code env:NAME}),
     * inline ASCII-armored key content, or a filesystem path.
     */
    public static final String PUBLIC_KEY_PATH = "publicKeyPath";
    /** Private (secret) key location; same multi-source scheme as {@link #PUBLIC_KEY_PATH}. */
    public static final String PRIVATE_KEY_PATH = "privateKeyPath";
    /** Passphrase protecting the private key; supply via a secure expression (e.g. {@code $secret:...}). */
    public static final String PASSPHRASE = "passphrase";

    // ---- Connection (key store) parameters ----------------------------------
    /** Connection type discriminator read by the init operation ({@code PGP_PRIVATE_KEY} / {@code PGP_PUBLIC_KEY}). */
    public static final String CONNECTION_TYPE = "connectionType";
    /**
     * Unique connection name; the value the operation connection pickers resolve to. The MI
     * connection framework passes this as the {@code name} template parameter (the {@code <name>}
     * element the tooling writes into the connection local entry), matching the convention used by
     * the WSO2 reference connectors — not {@code connectionName}, which is only the uischema field id.
     */
    public static final String CONNECTION_NAME = "name";
    /**
     * The single key identifier bound to a key store connection: a full fingerprint (40 hex for a
     * v4 key) or a 16-hex 64-bit Key ID. Auto-routed by {@link org.wso2.carbon.connector.cryptography.pgp.model.KeySelector#of(String)}.
     * Used to pick the recipient (encrypt) / signer (sign); optional for decrypt / verify, which
     * match the key from the message itself.
     */
    public static final String KEY_IDENTIFIER = "keyIdentifier";
    /** Operation reference to a public (trust) key store connection — encrypt / recipient side. */
    public static final String ENCRYPTION_CONFIG_KEY = "encryptionConfigKey";
    /** Operation reference to a private (identity) key store connection — decrypt side. */
    public static final String DECRYPTION_CONFIG_KEY = "decryptionConfigKey";
    /** Operation reference to a private (identity) key store connection — signing side. */
    public static final String SIGNING_CONFIG_KEY = "signingConfigKey";
    /** Operation reference to a public (trust) key store connection — verify / signer side. */
    public static final String VERIFICATION_CONFIG_KEY = "verificationConfigKey";


    public static final String SYMMETRIC_KEY_ALGORITHM = "symmetricKeyAlgorithm";
    public static final String COMPRESSION_ALGORITHM = "compressionAlgorithm";
    public static final String SIGNATURE_HASH_ALGORITHM = "signatureHashAlgorithm";
    public static final String ARMOR = "armor";
    /** Outbound: add an integrity-protection (MDC) packet to encrypted output. Default {@code true}. */
    public static final String INTEGRITY_CHECK = "integrityCheck";
    /** Inbound: reject decrypted messages that carry no integrity-protection (MDC). Default {@code true}. */
    public static final String REQUIRE_INTEGRITY = "requireIntegrity";
    /** Inbound: reject signatures made with a revoked or expired signer key. Default {@code true}. */
    public static final String REQUIRE_VALID_SIGNER_KEY = "requireValidSignerKey";
    public static final String FILE_NAME = "fileName";
}
