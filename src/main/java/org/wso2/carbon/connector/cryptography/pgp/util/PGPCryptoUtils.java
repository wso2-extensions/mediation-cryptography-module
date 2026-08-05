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
package org.wso2.carbon.connector.cryptography.pgp.util;

import org.wso2.carbon.connector.cryptography.pgp.constant.PGPCryptoConstants;
import org.wso2.carbon.connector.cryptography.pgp.model.LiteralData;
import org.wso2.carbon.connector.cryptography.pgp.model.VerificationResult;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.wso2.carbon.connector.cryptography.exception.CryptoException;
import org.wso2.carbon.connector.cryptography.exception.CryptoError;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;

/**
 * Stateless OpenPGP operations built on Bouncy Castle.
 *
 * <p>Implements the six operations finalized for the module:</p>
 * <ul>
 *   <li>{@link #encrypt} / {@link #decrypt}</li>
 *   <li>{@link #sign} / {@link #verify}</li>
 *   <li>{@link #signAndEncrypt} (outbound) / {@link #decryptAndVerify} (inbound)</li>
 * </ul>
 *
 * <p>Signed messages use the standard one-pass-signature layout
 * (compressed: one-pass-signature, literal data, signature) so they
 * interoperate with GnuPG and other OpenPGP implementations. 
 * 
 * Encryption uses a one-time session key wrapped with the recipient's public key (hybrid encryption) 
 * and an integrity (MDC) packet by default.</p>
 */
public final class PGPCryptoUtils {

    private static final int BUFFER_SIZE = 1 << 16;

    /**
     * Shared CSPRNG for session-key generation. A single seeded instance is thread-safe and avoids
     * the per-operation seeding cost (and potential blocking) of constructing a new {@link SecureRandom}.
     */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private PGPCryptoUtils() {
    }

    /**
     * Encrypt data for a single recipient using hybrid public-key encryption: a one-time
     * symmetric session key encrypts the (optionally compressed) literal data, and that
     * session key is wrapped with the recipient's public key.
     *
     * @param plainData            the raw bytes to encrypt.
     * @param encryptionKey        the recipient's public (encryption) key.
     * @param symmetricAlgorithm   OpenPGP symmetric-key algorithm tag for the session key
     *                             (see {@link PGPCryptoConstants#resolveSymmetricKeyAlgorithm}).
     * @param compressionAlgorithm OpenPGP compression algorithm tag
     *                             (see {@link PGPCryptoConstants#resolveCompressionAlgorithm}).
     * @param armor                {@code true} to ASCII-armor the output, {@code false} for binary.
     * @param withIntegrityCheck   {@code true} to add an integrity-protection (MDC) packet.
     * @param textMode             {@code true} to tag the literal-data packet as UTF-8 text
     *                             ({@code 'u'}), {@code false} to tag it as binary ({@code 'b'}); the
     *                             recipient uses this to default its output carriage.
     * @param fileName             optional file name embedded in the literal-data packet;
     *                             {@code null} uses the default console name.
     * @return the encrypted message bytes (armored or binary per {@code armor}).
     * @throws CryptoException if encryption fails.
     */
    public static byte[] encrypt(byte[] plainData, PGPPublicKey encryptionKey, int symmetricAlgorithm,
                                 int compressionAlgorithm, boolean armor, boolean withIntegrityCheck,
                                 boolean textMode, String fileName) throws CryptoException {
        try {
            ByteArrayOutputStream compressed = new ByteArrayOutputStream();
            compressLiteralData(compressed, plainData, compressionAlgorithm, literalFormat(textMode), fileName);
            byte[] compressedBytes = compressed.toByteArray();

            ByteArrayOutputStream sink = new ByteArrayOutputStream();
            OutputStream target = armor ? new ArmoredOutputStream(sink) : sink;

            PGPEncryptedDataGenerator encGen =
                    newEncryptedDataGenerator(symmetricAlgorithm, encryptionKey, withIntegrityCheck);
            try (OutputStream encryptedOut = encGen.open(target, compressedBytes.length)) {
                encryptedOut.write(compressedBytes);
            }
            target.close();
            return sink.toByteArray();
        } catch (IOException | PGPException e) {
            throw new CryptoException(CryptoError.OPERATION_ERROR, "PGP encryption failed.", e);
        }
    }

    /**
     * Decrypt a public-key encrypted message. Scans the encrypted-data list for a session
     * key that one of the supplied secret keys can unwrap, decrypts the payload, and (when
     * present) verifies the integrity-protection (MDC) packet.
     *
     * @param cipherData       the encrypted message bytes (armored or binary).
     * @param secretKeys       the secret key-ring collection holding candidate decryption keys.
     * @param passphrase       the passphrase protecting the matching secret key.
     * @param requireIntegrity when {@code true}, reject a message that carries no integrity
     *                         -protection (MDC) packet rather than silently accepting it.
     * @return the decrypted payload together with any embedded literal-data metadata.
     * @throws CryptoException if no matching secret key is found, the integrity policy is
     *                         violated, the integrity check fails, or decryption otherwise fails.
     */
    public static LiteralData decrypt(byte[] cipherData, PGPSecretKeyRingCollection secretKeys,
                                      String passphrase, boolean requireIntegrity) throws CryptoException {
        try (InputStream decoded = PGPUtil.getDecoderStream(new ByteArrayInputStream(cipherData))) {
            JcaPGPObjectFactory factory = new JcaPGPObjectFactory(decoded);
            DecryptionMatch match = findDecryptionKey(readEncryptedDataList(factory), secretKeys, passphrase);

            LiteralData data;
            try (InputStream clear = match.encData.getDataStream(newDataDecryptor(match.privateKey))) {
                data = extractLiteralData(clear);
                // Must run after the data stream is fully read: the MDC trailer sits at its end.
                verifyIntegrity(match.encData, requireIntegrity);
            }
            return data;
        } catch (IOException | PGPException e) {
            throw new CryptoException(CryptoError.OPERATION_ERROR, "PGP decryption failed.", e);
        }
    }

    /**
     * Produce a one-pass-signed, compressed message. The output carries the payload together
     * with the signature, using the standard layout
     * {@code compressed( one-pass-signature, literal-data, signature )} so it interoperates
     * with GnuPG and other OpenPGP implementations.
     *
     * @param data                 the raw bytes to sign.
     * @param signingKey           the signer's secret key (supplies the public-key algorithm).
     * @param privateKey           the unlocked private key used to generate the signature.
     * @param hashAlgorithm        OpenPGP hash algorithm tag for the signature
     *                             (see {@link PGPCryptoConstants#resolveHashAlgorithm}).
     * @param compressionAlgorithm OpenPGP compression algorithm tag.
     * @param armor                {@code true} to ASCII-armor the output, {@code false} for binary.
     * @param textMode             {@code true} to tag the literal-data packet as UTF-8 text
     *                             ({@code 'u'}), {@code false} as binary ({@code 'b'}).
     * @param fileName             optional file name embedded in the literal-data packet;
     *                             {@code null} uses the default console name.
     * @return the signed message bytes (armored or binary per {@code armor}).
     * @throws CryptoException if signing fails.
     */
    public static byte[] sign(byte[] data, PGPSecretKey signingKey, PGPPrivateKey privateKey,
                              int hashAlgorithm, int compressionAlgorithm, boolean armor,
                              boolean textMode, String fileName) throws CryptoException {
        try {
            ByteArrayOutputStream sink = new ByteArrayOutputStream();
            OutputStream target = armor ? new ArmoredOutputStream(sink) : sink;
            writeSignedMessage(target, data, signingKey, privateKey, hashAlgorithm,
                    compressionAlgorithm, literalFormat(textMode), fileName);
            target.close();
            return sink.toByteArray();
        } catch (IOException | PGPException e) {
            throw new CryptoException(CryptoError.OPERATION_ERROR, "PGP signing failed.", e);
        }
    }

    /**
     * Verify a one-pass-signed message and recover its payload. The signer's key is located
     * in the supplied public key-ring collection by the signature's key ID.
     *
     * @param signedData the signed message bytes (armored or binary).
     * @param publicKeys the public key-ring collection used to locate the signer's key.
     * @return a {@link VerificationResult} carrying the recovered payload and the validity flag.
     * @throws CryptoException if the message is not signed, the signer's key is missing,
     *                         or verification otherwise fails.
     */
    public static VerificationResult verify(byte[] signedData, PGPPublicKeyRingCollection publicKeys,
                                            boolean requireValidSignerKey) throws CryptoException {
        try (InputStream decoded = PGPUtil.getDecoderStream(new ByteArrayInputStream(signedData))) {
            return verifyFromStream(decoded, publicKeys, requireValidSignerKey);
        } catch (IOException e) {
            throw new CryptoException(CryptoError.OPERATION_ERROR, "PGP verification failed.", e);
        }
    }

    /**
     * Sign then encrypt in a single pass (the outbound combined operation): the signed,
     * compressed payload is written straight into the encryption stream, so the signature
     * is concealed inside the ciphertext rather than exposed alongside it.
     *
     * @param data                 the raw bytes to sign and encrypt.
     * @param encryptionKey        the recipient's public (encryption) key.
     * @param signingKey           the signer's secret key (supplies the public-key algorithm).
     * @param privateKey           the unlocked private key used to generate the signature.
     * @param symmetricAlgorithm   OpenPGP symmetric-key algorithm tag for the session key.
     * @param compressionAlgorithm OpenPGP compression algorithm tag.
     * @param hashAlgorithm        OpenPGP hash algorithm tag for the signature.
     * @param armor                {@code true} to ASCII-armor the output, {@code false} for binary.
     * @param withIntegrityCheck   {@code true} to add an integrity-protection (MDC) packet.
     * @param textMode             {@code true} to tag the literal-data packet as UTF-8 text
     *                             ({@code 'u'}), {@code false} as binary ({@code 'b'}).
     * @param fileName             optional file name embedded in the literal-data packet;
     *                             {@code null} uses the default console name.
     * @return the signed-then-encrypted message bytes (armored or binary per {@code armor}).
     * @throws CryptoException if the combined operation fails.
     */
    public static byte[] signAndEncrypt(byte[] data, PGPPublicKey encryptionKey, PGPSecretKey signingKey,
                                        PGPPrivateKey privateKey, int symmetricAlgorithm,
                                        int compressionAlgorithm, int hashAlgorithm, boolean armor,
                                        boolean withIntegrityCheck, boolean textMode, String fileName)
            throws CryptoException {
        try {
            ByteArrayOutputStream sink = new ByteArrayOutputStream();
            OutputStream target = armor ? new ArmoredOutputStream(sink) : sink;

            PGPEncryptedDataGenerator encGen =
                    newEncryptedDataGenerator(symmetricAlgorithm, encryptionKey, withIntegrityCheck);
            // The signed-and-compressed payload is written directly into the encryption stream.
            try (OutputStream encryptedOut = encGen.open(target, new byte[BUFFER_SIZE])) {
                writeSignedMessage(encryptedOut, data, signingKey, privateKey, hashAlgorithm,
                        compressionAlgorithm, literalFormat(textMode), fileName);
            }
            target.close();
            return sink.toByteArray();
        } catch (IOException | PGPException e) {
            throw new CryptoException(CryptoError.OPERATION_ERROR, "PGP sign-then-encrypt failed.", e);
        }
    }

    /**
     * Decrypt then verify in a single pass (the inbound combined operation): the message is
     * decrypted with a matching secret key, the embedded signature is verified against the
     * supplied public keys, and the integrity-protection (MDC) packet is checked when present.
     *
     * @param cipherData       the signed-then-encrypted message bytes (armored or binary).
     * @param secretKeys       the secret key-ring collection holding candidate decryption keys.
     * @param publicKeys       the public key-ring collection used to locate the signer's key.
     * @param passphrase       the passphrase protecting the matching secret key.
     * @param requireIntegrity when {@code true}, reject a message that carries no integrity
     *                         -protection (MDC) packet rather than silently accepting it.
     * @param requireValidSignerKey when {@code true}, reject a signature made with a revoked or
     *                         (at signing time) expired signer key.
     * @return a {@link VerificationResult} carrying the recovered payload and the validity flag.
     * @throws CryptoException if no matching secret key is found, the integrity policy is
     *                         violated, the integrity check fails, or the operation otherwise fails.
     */
    public static VerificationResult decryptAndVerify(byte[] cipherData,
                                                      PGPSecretKeyRingCollection secretKeys,
                                                      PGPPublicKeyRingCollection publicKeys,
                                                      String passphrase,
                                                      boolean requireIntegrity,
                                                      boolean requireValidSignerKey) throws CryptoException {
        try (InputStream decoded = PGPUtil.getDecoderStream(new ByteArrayInputStream(cipherData))) {
            JcaPGPObjectFactory factory = new JcaPGPObjectFactory(decoded);
            DecryptionMatch match = findDecryptionKey(readEncryptedDataList(factory), secretKeys, passphrase);

            VerificationResult result;
            try (InputStream clear = match.encData.getDataStream(newDataDecryptor(match.privateKey))) {
                result = verifyFromStream(clear, publicKeys, requireValidSignerKey);
                // Must run after the data stream is fully read: the MDC trailer sits at its end.
                verifyIntegrity(match.encData, requireIntegrity);
            }
            return result;
        } catch (IOException | PGPException e) {
            throw new CryptoException(CryptoError.OPERATION_ERROR, "PGP decrypt-then-verify failed.", e);
        }
    }

    /**
     * Enforce the inbound integrity policy on a decrypted message. When {@code requireIntegrity}
     * is set, a message lacking an integrity-protection (MDC) packet is rejected outright; in all
     * cases, when an MDC packet is present it must verify. Must be called only after the data
     * stream has been fully read, because the MDC trailer sits at the end of the ciphertext.
     */
    private static void verifyIntegrity(PGPPublicKeyEncryptedData encData, boolean requireIntegrity)
            throws IOException, PGPException, CryptoException {
        if (!encData.isIntegrityProtected()) {
            if (requireIntegrity) {
                throw new CryptoException(CryptoError.INTEGRITY_PROTECTION_MISSING,
                        "Rejected: message is not integrity-protected (no MDC packet). "
                        + "Set requireIntegrity=false to accept unprotected messages from legacy partners.");
            }
            return;
        }
        if (!encData.verify()) {
            throw new CryptoException(CryptoError.INTEGRITY_CHECK_FAILED,
                    "Integrity check failed: message may have been tampered with.");
        }
    }

    /**
     * Write a compressed, one-pass-signed literal-data message to {@code out}.
     * Layout: compressed( one-pass-signature, literal-data, signature ).
     *
     * <p>The signature is always computed over the raw payload bytes ({@code BINARY_DOCUMENT}); the
     * {@code literalFormat} byte tags the enclosed literal-data packet only and does not affect the
     * bytes that are signed, so it is interoperable with any OpenPGP verifier.</p>
     */
    private static void writeSignedMessage(OutputStream out, byte[] data, PGPSecretKey signingKey,
                                           PGPPrivateKey privateKey, int hashAlgorithm,
                                           int compressionAlgorithm, char literalFormat, String fileName)
            throws IOException, PGPException {
        String literalName = (fileName == null) ? PGPLiteralData.CONSOLE : fileName;

        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(signingKey.getPublicKey().getAlgorithm(), hashAlgorithm)
                        .setProvider(PGPCryptoConstants.BC_PROVIDER),
                signingKey.getPublicKey());
        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);

        PGPCompressedDataGenerator compGen = new PGPCompressedDataGenerator(compressionAlgorithm);
        OutputStream compressedOut = compGen.open(out);

        signatureGenerator.generateOnePassVersion(false).encode(compressedOut);

        PGPLiteralDataGenerator literalGen = new PGPLiteralDataGenerator();
        OutputStream literalOut = literalGen.open(compressedOut, literalFormat, literalName,
                new Date(), new byte[BUFFER_SIZE]);
        literalOut.write(data);
        signatureGenerator.update(data);
        literalGen.close();

        signatureGenerator.generate().encode(compressedOut);
        compGen.close();
    }

    /** Map the connector's text/binary intent onto the OpenPGP literal-data format byte. */
    private static char literalFormat(boolean textMode) {
        return textMode ? PGPLiteralData.UTF8 : PGPLiteralData.BINARY;
    }

    /**
     * Read a one-pass-signed message from a (possibly already decrypted) clear stream,
     * recover the payload, and verify the signature against the supplied public keys. When
     * {@code requireValidSignerKey} is set, a signature made with a revoked or expired signer key
     * is rejected even if it is cryptographically valid.
     */
    private static VerificationResult verifyFromStream(InputStream clearStream,
                                                       PGPPublicKeyRingCollection publicKeys,
                                                       boolean requireValidSignerKey)
            throws CryptoException {
        InputStream compressed = null;
        try {
            JcaPGPObjectFactory factory = new JcaPGPObjectFactory(clearStream);
            Object object = factory.nextObject();

            if (object instanceof PGPCompressedData) {
                compressed = ((PGPCompressedData) object).getDataStream();
                factory = new JcaPGPObjectFactory(compressed);
                object = factory.nextObject();
            }

            if (!(object instanceof PGPOnePassSignatureList)) {
                throw new CryptoException(CryptoError.INVALID_MESSAGE_FORMAT,
                        "Message is not signed (no one-pass-signature found).");
            }
            PGPOnePassSignature onePass = ((PGPOnePassSignatureList) object).get(0);

            PGPPublicKey publicKey = publicKeys.getPublicKey(onePass.getKeyID());
            if (publicKey == null) {
                throw new CryptoException(CryptoError.KEY_NOT_FOUND, "Public key for signer (key ID "
                        + Long.toHexString(onePass.getKeyID()) + ") not found.");
            }
            onePass.init(new JcaPGPContentVerifierBuilderProvider()
                    .setProvider(PGPCryptoConstants.BC_PROVIDER), publicKey);

            object = factory.nextObject();
            if (!(object instanceof PGPLiteralData)) {
                throw new CryptoException(CryptoError.INVALID_MESSAGE_FORMAT,
                        "Malformed signed message: literal data expected.");
            }
            PGPLiteralData literalData = (PGPLiteralData) object;

            ByteArrayOutputStream payload = new ByteArrayOutputStream();
            try (InputStream literalInput = literalData.getInputStream()) {
                byte[] buffer = new byte[BUFFER_SIZE];
                int read;
                while ((read = literalInput.read(buffer)) >= 0) {
                    payload.write(buffer, 0, read);
                    onePass.update(buffer, 0, read);
                }
            }

            object = factory.nextObject();
            if (!(object instanceof PGPSignatureList)) {
                throw new CryptoException(CryptoError.INVALID_MESSAGE_FORMAT,
                        "Malformed signed message: signature packet expected.");
            }
            PGPSignature signature = ((PGPSignatureList) object).get(0);
            boolean valid = onePass.verify(signature);

            if (requireValidSignerKey) {
                PGPKeyUtils.validateSignerKey(publicKey, signature.getCreationTime());
            }
            return new VerificationResult(toLiteralData(literalData, payload.toByteArray()), valid);
        } catch (IOException | PGPException e) {
            throw new CryptoException(CryptoError.OPERATION_ERROR, "Signature verification failed.", e);
        } finally {
            closeQuietly(compressed);
        }
    }

    /** Compress raw bytes into a literal-data packet (no signature) for the encrypt-only path. */
    private static void compressLiteralData(OutputStream out, byte[] data, int compressionAlgorithm,
                                            char literalFormat, String fileName) throws IOException {
        String literalName = (fileName == null) ? PGPLiteralData.CONSOLE : fileName;
        PGPCompressedDataGenerator compGen = new PGPCompressedDataGenerator(compressionAlgorithm);
        OutputStream compressedOut = compGen.open(out);
        PGPLiteralDataGenerator literalGen = new PGPLiteralDataGenerator();
        OutputStream literalOut = literalGen.open(compressedOut, literalFormat, literalName,
                data.length, new Date());
        literalOut.write(data);
        literalGen.close();
        compGen.close();
    }

    /** Read the payload and embedded metadata out of a (possibly compressed) literal-data stream. */
    private static LiteralData extractLiteralData(InputStream clearStream) throws IOException, PGPException {
        InputStream compressed = null;
        try {
            JcaPGPObjectFactory factory = new JcaPGPObjectFactory(clearStream);
            Object object = factory.nextObject();
            if (object instanceof PGPCompressedData) {
                compressed = ((PGPCompressedData) object).getDataStream();
                factory = new JcaPGPObjectFactory(compressed);
                object = factory.nextObject();
            }
            if (!(object instanceof PGPLiteralData)) {
                throw new PGPException("Expected literal data in the decrypted message.");
            }
            PGPLiteralData literalData = (PGPLiteralData) object;
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (InputStream in = literalData.getInputStream()) {
                byte[] buffer = new byte[BUFFER_SIZE];
                int read;
                while ((read = in.read(buffer)) >= 0) {
                    out.write(buffer, 0, read);
                }
            }
            return toLiteralData(literalData, out.toByteArray());
        } finally {
            closeQuietly(compressed);
        }
    }

    /** Close a stream, ignoring a null reference and any close-time error (best-effort cleanup). */
    private static void closeQuietly(InputStream stream) {
        if (stream == null) {
            return;
        }
        try {
            stream.close();
        } catch (IOException ignored) {
            // Best-effort: the payload has already been read; a close-time failure is not actionable.
        }
    }

    /**
     * Wrap recovered payload bytes with the metadata embedded in the OpenPGP literal-data packet.
     * The {@code _CONSOLE} file-name sentinel (the default when no name was set) and an epoch
     * modification time (the OpenPGP "unspecified" value) are normalised to {@code null} so the
     * operation only surfaces meaningful values.
     */
    private static LiteralData toLiteralData(PGPLiteralData literalData, byte[] data) {
        String fileName = literalData.getFileName();
        if (fileName == null || fileName.isEmpty() || PGPLiteralData.CONSOLE.equals(fileName)) {
            fileName = null;
        }
        Date modificationTime = literalData.getModificationTime();
        if (modificationTime == null || modificationTime.getTime() == 0L) {
            modificationTime = null;
        }
        return new LiteralData(data, fileName, modificationTime, (char) literalData.getFormat());
    }

    /**
     * Read the {@link PGPEncryptedDataList} from the object stream, skipping a leading PGP
     * marker packet if one is present.
     *
     * @param factory the object factory wrapping the decoded input stream.
     * @return the encrypted-data list.
     * @throws CryptoException if the input is not a public-key encrypted message.
     * @throws IOException     if reading the stream fails.
     */
    private static PGPEncryptedDataList readEncryptedDataList(JcaPGPObjectFactory factory)
            throws IOException, CryptoException {
        Object object = factory.nextObject();
        // Skip a leading PGP marker packet if present.
        if (!(object instanceof PGPEncryptedDataList)) {
            object = factory.nextObject();
        }
        if (!(object instanceof PGPEncryptedDataList)) {
            throw new CryptoException(CryptoError.INVALID_MESSAGE_FORMAT,
                    "Input is not a PGP public-key encrypted message.");
        }
        return (PGPEncryptedDataList) object;
    }

    /** Build a public-key encrypted-data generator for a single recipient (shared by the encrypt paths). */
    private static PGPEncryptedDataGenerator newEncryptedDataGenerator(int symmetricAlgorithm,
            PGPPublicKey encryptionKey, boolean withIntegrityCheck) {
        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(symmetricAlgorithm)
                        .setWithIntegrityPacket(withIntegrityCheck)
                        .setSecureRandom(SECURE_RANDOM)
                        .setProvider(PGPCryptoConstants.BC_PROVIDER));
        encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey)
                .setProvider(PGPCryptoConstants.BC_PROVIDER));
        return encGen;
    }

    /** Build the session-key decryptor factory for an unlocked private key (shared by the decrypt paths). */
    private static PublicKeyDataDecryptorFactory newDataDecryptor(PGPPrivateKey privateKey) throws PGPException {
        return new JcePublicKeyDataDecryptorFactoryBuilder()
                .setProvider(PGPCryptoConstants.BC_PROVIDER)
                .build(privateKey);
    }

    /**
     * Scan the encrypted-data list for the first session key that one of the supplied secret keys can
     * unwrap, and unlock the matching private key with the passphrase. Shared by decrypt / decryptAndVerify.
     *
     * @throws CryptoException if no candidate secret key matches, or the passphrase is wrong.
     */
    private static DecryptionMatch findDecryptionKey(PGPEncryptedDataList encList,
            PGPSecretKeyRingCollection secretKeys, String passphrase) throws PGPException, CryptoException {
        for (Iterator<?> it = encList.getEncryptedDataObjects(); it.hasNext(); ) {
            PGPPublicKeyEncryptedData candidate = (PGPPublicKeyEncryptedData) it.next();
            PGPSecretKey secretKey = secretKeys.getSecretKey(candidate.getKeyIdentifier().getKeyId());
            if (secretKey != null) {
                return new DecryptionMatch(PGPKeyUtils.extractPrivateKey(secretKey, passphrase), candidate);
            }
        }
        throw new CryptoException(CryptoError.KEY_NOT_FOUND,
                "No matching secret key found to decrypt the message.");
    }

    /** A matched, unlocked private key together with the encrypted-data object it decrypts. */
    private static final class DecryptionMatch {
        private final PGPPrivateKey privateKey;
        private final PGPPublicKeyEncryptedData encData;

        DecryptionMatch(PGPPrivateKey privateKey, PGPPublicKeyEncryptedData encData) {
            this.privateKey = privateKey;
            this.encData = encData;
        }
    }
}
