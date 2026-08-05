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

import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.util.Locale;

/**
 * Template parameter names, defaults, and the mapping from human-friendly
 * algorithm names to Bouncy Castle / OpenPGP numeric algorithm tags.
 *
 * <p>The supported algorithm sets follow the OpenPGP registries defined in
 * RFC 4880 and RFC 9580 (sections 9.2 / 9.3 / 9.4) which all build on Bouncy
 * Castle. Modern, recommended algorithms are the defaults and legacy algorithms
 * are accepted for interoperability with older partners.</p>
 */
public final class PGPCryptoConstants {

    private PGPCryptoConstants() {
    }

    // Carriage selectors — how the bytes sit in the MI message body / variable.
    /** Plain text in the body (text/plain). For armored PGP or plain text. */
    public static final String MSG_TYPE_TEXT = "TEXT";
    /** Base64 text in the body (text/plain). HTTP/JSON-safe carriage for binary bytes. */
    public static final String MSG_TYPE_BASE64 = "BASE64";
    /** Raw bytes in the body (application/octet-stream). Byte-faithful for File connector / VFS. */
    public static final String MSG_TYPE_BINARY = "BINARY";

    /**
     * Leading marker of every ASCII-armored OpenPGP block. Inbound operations use it to detect and
     * extract the armored region from the source content (see {@code AbstractPGPOperation.readPgpInput}).
     */
    public static final String ARMOR_HEADER_PREFIX = "-----BEGIN PGP";

    // Response-variable attribute names populated by the inbound operations.
    /** Boolean attribute: whether the signature verified (verify / decryptAndVerify). */
    public static final String ATTR_SIGNATURE_VALID = "signatureValid";
    /** Optional attribute: the file name embedded in the OpenPGP literal-data packet. */
    public static final String ATTR_FILE_NAME = "fileName";
    /** Optional attribute: the modification time (ISO-8601) embedded in the literal-data packet. */
    public static final String ATTR_MODIFICATION_TIME = "modificationTime";

    // Content types used when writing the operation output to the message body
    public static final String CONTENT_TYPE_TEXT = "text/plain";
    public static final String CONTENT_TYPE_BINARY = "application/octet-stream";

    /** Charset used for TEXT input/output when none is specified. */
    public static final String DEFAULT_CHARSET = "UTF-8";

    // Defaults Values
    /** AES-256 is the modern interoperable default used by GnuPG and every peer platform. */
    public static final String DEFAULT_SYMMETRIC_ALGORITHM = "AES_256";
    /** ZLIB is widely supported and a safe default and ZIP is the most universally compatible. */
    public static final String DEFAULT_COMPRESSION_ALGORITHM = "ZLIB";
    /** SHA-256 is the recommended baseline digest for signatures. */
    public static final String DEFAULT_HASH_ALGORITHM = "SHA256";
    public static final boolean DEFAULT_ARMOR = false;
    public static final boolean DEFAULT_INTEGRITY_CHECK = true;
    /**
     * Inbound integrity policy default. When {@code true}, decrypt / decryptAndVerify reject a
     * message that carries no integrity-protection (MDC) packet, matching the modern OpenPGP
     * posture (e.g. GnuPG refuses unprotected messages for modern ciphers).
     */
    public static final boolean DEFAULT_REQUIRE_INTEGRITY = true;
    /**
     * Inbound signer-key trust policy default. When {@code true}, verify / decryptAndVerify reject a
     * signature made with a revoked or (at signing time) expired signer key, even if the signature is
     * cryptographically valid. Set to {@code false} to accept such signatures from legacy partners.
     */
    public static final boolean DEFAULT_REQUIRE_VALID_SIGNER_KEY = true;

    /**
     * Shared Bouncy Castle provider instance, passed directly to the JCA/JCE builders.
     * Using the instance (rather than the registered "BC" name) keeps the connector
     * self-contained: it does not mutate the JVM-global {@link java.security.Security}
     * provider list and does not depend on the container having registered Bouncy Castle.
     */
    public static final Provider BC_PROVIDER = new BouncyCastleProvider();

    /**
     * Resolve an OpenPGP symmetric-key algorithm tag from a friendly name.
     * Recommended: AES_256, AES_192, AES_128, CAMELLIA_256, TWOFISH.
     * Legacy (accepted for interop, discouraged): CAST5, TRIPLE_DES, BLOWFISH, IDEA.
     */
    public static int resolveSymmetricKeyAlgorithm(String name) {
        if (name == null || name.trim().isEmpty()) {
            name = DEFAULT_SYMMETRIC_ALGORITHM;
        }
        switch (normalize(name)) {
            case "AES_128":
            case "AES128":
                return SymmetricKeyAlgorithmTags.AES_128;
            case "AES_192":
            case "AES192":
                return SymmetricKeyAlgorithmTags.AES_192;
            case "AES_256":
            case "AES256":
                return SymmetricKeyAlgorithmTags.AES_256;
            case "TWOFISH":
                return SymmetricKeyAlgorithmTags.TWOFISH;
            case "CAMELLIA_128":
                return SymmetricKeyAlgorithmTags.CAMELLIA_128;
            case "CAMELLIA_192":
                return SymmetricKeyAlgorithmTags.CAMELLIA_192;
            case "CAMELLIA_256":
                return SymmetricKeyAlgorithmTags.CAMELLIA_256;
            case "CAST5":
                return SymmetricKeyAlgorithmTags.CAST5;
            case "TRIPLE_DES":
            case "3DES":
            case "TRIPLEDES":
                return SymmetricKeyAlgorithmTags.TRIPLE_DES;
            case "BLOWFISH":
                return SymmetricKeyAlgorithmTags.BLOWFISH;
            case "IDEA":
                return SymmetricKeyAlgorithmTags.IDEA;
            default:
                throw new IllegalArgumentException("Unsupported symmetric key algorithm: " + name);
        }
    }

    /**
     * Resolve an OpenPGP compression algorithm tag from a friendly name.
     * UNCOMPRESSED, ZIP (RFC 1951), ZLIB (RFC 1950), BZIP2.
     */
    public static int resolveCompressionAlgorithm(String name) {
        if (name == null || name.trim().isEmpty()) {
            name = DEFAULT_COMPRESSION_ALGORITHM;
        }
        switch (normalize(name)) {
            case "UNCOMPRESSED":
            case "NONE":
                return CompressionAlgorithmTags.UNCOMPRESSED;
            case "ZIP":
                return CompressionAlgorithmTags.ZIP;
            case "ZLIB":
                return CompressionAlgorithmTags.ZLIB;
            case "BZIP2":
                return CompressionAlgorithmTags.BZIP2;
            default:
                throw new IllegalArgumentException("Unsupported compression algorithm: " + name);
        }
    }

    /**
     * Resolve an OpenPGP hash (message digest) algorithm tag from a friendly name.
     * Recommended: SHA256, SHA384, SHA512. 
     * Legacy (accepted for interop, discouraged): SHA224, SHA1, RIPEMD160.
     */
    public static int resolveHashAlgorithm(String name) {
        if (name == null || name.trim().isEmpty()) {
            name = DEFAULT_HASH_ALGORITHM;
        }
        switch (normalize(name)) {
            case "SHA256":
            case "SHA_256":
                return HashAlgorithmTags.SHA256;
            case "SHA384":
            case "SHA_384":
                return HashAlgorithmTags.SHA384;
            case "SHA512":
            case "SHA_512":
                return HashAlgorithmTags.SHA512;
            case "SHA224":
            case "SHA_224":
                return HashAlgorithmTags.SHA224;
            case "SHA1":
            case "SHA_1":
                return HashAlgorithmTags.SHA1;
            case "RIPEMD160":
                return HashAlgorithmTags.RIPEMD160;
            default:
                throw new IllegalArgumentException("Unsupported signature hash algorithm: " + name);
        }
    }

    /**
     * Resolve and validate a carriage selector ({@code TEXT}, {@code BASE64} or {@code BINARY}),
     * falling back to {@code defaultType} when not supplied.
     */
    public static String resolveMessageType(String value, String defaultType) {
        if (value == null || value.trim().isEmpty()) {
            return defaultType;
        }
        String v = normalize(value);
        switch (v) {
            case MSG_TYPE_TEXT:
            case MSG_TYPE_BASE64:
            case MSG_TYPE_BINARY:
                return v;
            default:
                throw new IllegalArgumentException(
                        "Unsupported message type: " + value + " (expected TEXT, BASE64 or BINARY).");
        }
    }

    private static String normalize(String value) {
        return value.trim().toUpperCase(Locale.ENGLISH);
    }
}
