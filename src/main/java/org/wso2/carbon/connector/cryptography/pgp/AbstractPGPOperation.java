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
package org.wso2.carbon.connector.cryptography.pgp;

import com.google.gson.JsonPrimitive;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMNode;
import org.apache.axiom.om.OMText;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseConstants;
import org.apache.synapse.SynapseException;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.wso2.integration.connector.core.AbstractConnectorOperation;
import org.wso2.integration.connector.core.ConnectException;
import org.wso2.integration.connector.core.util.PayloadUtils;
import org.wso2.carbon.connector.cryptography.exception.CryptoException;
import org.wso2.carbon.connector.cryptography.exception.CryptoError;
import org.wso2.carbon.connector.cryptography.pgp.connection.PgpKeyStore;
import org.wso2.carbon.connector.cryptography.pgp.connection.PgpKeyStoreHandler;
import org.wso2.carbon.connector.cryptography.pgp.constant.PGPCryptoConstants;
import org.wso2.carbon.connector.cryptography.pgp.constant.PGPParameterKey;

import javax.activation.DataHandler;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Base class for the PGP operations, built on the connector-core
 * {@link AbstractConnectorOperation} model (the same one used by the WSO2 utility connector).
 *
 * <p>Each operation reads its input as bytes, runs a Bouncy Castle PGP operation, and emits the
 * result through {@link #handleConnectorResponse} so the standard {@code responseVariable} and
 * {@code overwriteBody} behaviour is handled natively by the framework:</p>
 *
 * <ul>
 *   <li><b>Input</b> — the {@code sourceContent} expression ({@code ${payload}} / {@code ${vars.x}}
 *       / a property). {@code inputType} (TEXT / BASE64 / BINARY) says how to turn it into bytes.</li>
 *   <li><b>Output</b> — written to the {@code responseVariable} payload (when {@code overwriteBody}
 *       is false, preserving the original message body) or to the message body (when true), in the
 *       requested carriage (TEXT/BASE64 = text, BINARY = raw application/octet-stream).</li>
 *   <li><b>Signature verdict</b> — the verify operations also place {@code signatureValid} in the
 *       response variable's {@code attributes}.</li>
 * </ul>
 *
 * <p>No instance state is held between invocations; the implementation must remain stateless
 * because multiple mediation threads share the instance.</p>
 */
public abstract class AbstractPGPOperation extends AbstractConnectorOperation {

    /** The actual operation logic implemented by each concrete operation. */
    protected abstract void executePgp(MessageContext mc, String responseVariable, Boolean overwriteBody)
            throws CryptoException;

    /** Short operation name for logging. */
    protected abstract String operationName();

    @Override
    public void execute(MessageContext mc, String responseVariable, Boolean overwriteBody)
            throws ConnectException {
        try {
            executePgp(mc, responseVariable, overwriteBody);
        } catch (CryptoException e) {
            fail(mc, e.getError(), e);
        } catch (IllegalArgumentException e) {
            // Unsupported algorithm / message-type names surface as IllegalArgumentException
            // from the PGPCryptoConstants.resolve* helpers; classify them as configuration errors.
            fail(mc, CryptoError.INVALID_CONFIGURATION, e);
        } catch (Exception e) {
            fail(mc, CryptoError.GENERAL_ERROR, e);
        }
    }

    /**
     * Publish the failure to the message context as the module's {@code 7013xx} error code and
     * tag (so a fault sequence can branch on {@code ERROR_CODE} / {@code ERROR_MESSAGE}), log it,
     * and raise a {@link SynapseException} to enter fault handling. Never returns.
     */
    private void fail(MessageContext mc, CryptoError error, Exception e) {
        mc.setProperty(SynapseConstants.ERROR_CODE, error.getErrorCode());
        mc.setProperty(SynapseConstants.ERROR_MESSAGE, error.getErrorMessage());
        mc.setProperty(SynapseConstants.ERROR_DETAIL, e.getMessage());
        mc.setProperty(SynapseConstants.ERROR_EXCEPTION, e);
        log.error("[cryptography:" + operationName() + "] [" + error.getErrorCode() + " "
                + error.getErrorMessage() + "] " + e.getMessage(), e);
        throw new SynapseException(e.getMessage(), e);
    }

    /**
     * Read the operation input as bytes from the {@code sourceContent} expression (already resolved
     * by the synapse template engine).
     *
     * <ul>
     *   <li>{@code TEXT} → charset-decode the string.</li>
     *   <li>{@code BASE64} / {@code BINARY} → base64-decode the string. (A File/VFS transport
     *       delivers a binary file's content as base64 in the body, so base64 decoding recovers the
     *       raw bytes in both cases.)</li>
     * </ul>
     *
     * @param mc     the message context.
     * @param inType the input carriage: {@code TEXT}, {@code BASE64} or {@code BINARY}.
     */
    protected byte[] readInput(MessageContext mc, String inType) throws CryptoException {
        if (!readsFromExpression(mc)) {
            // Message-body source: read the raw payload bytes directly (binary-safe).
            return readMessageBodyBytes(mc);
        }
        String content = requireSourceContent(mc);
        if (PGPCryptoConstants.MSG_TYPE_TEXT.equals(inType)) {
            return content.getBytes(charset(mc));
        }
        try {
            return Base64.getMimeDecoder().decode(content.trim());
        } catch (IllegalArgumentException e) {
            throw new CryptoException(CryptoError.INVALID_INPUT,
                    "Input is not valid base64 for " + inType + " inputType.", e);
        }
    }

    /**
     * Whether the operation reads its input from the {@code sourceContent} expression (a variable or
     * message field) rather than the raw message body. True when {@code inputSource} is explicitly
     * {@code Expression}, or — for backward compatibility — when a non-empty {@code sourceContent} was
     * supplied without the toggle. Defaults to the message body.
     */
    private boolean readsFromExpression(MessageContext mc) {
        String source = param(mc, PGPParameterKey.INPUT_SOURCE);
        if (source != null && PGPParameterKey.INPUT_SOURCE_EXPRESSION.equalsIgnoreCase(source.trim())) {
            return true;
        }
        String content = param(mc, PGPParameterKey.SOURCE_CONTENT);
        return content != null && !content.isEmpty();
    }

    private String requireSourceContent(MessageContext mc) throws CryptoException {
        String content = param(mc, PGPParameterKey.SOURCE_CONTENT);
        if (content == null || content.isEmpty()) {
            throw new CryptoException(CryptoError.INVALID_INPUT,
                    "Input Source is 'Expression' but no Source Content expression was provided.");
        }
        return content;
    }

    /**
     * Write the operation output (encrypt/sign); carries no verdict or metadata.
     */
    protected void emitResult(MessageContext mc, byte[] output, String outType,
                              String responseVariable, Boolean overwriteBody) {
        writeResponse(mc, output, outType, responseVariable, overwriteBody, null);
    }

    /**
     * Write the operation output together with the literal-data metadata (decrypt): the embedded
     * file name and modification time, when present, land in the response variable's attributes.
     */
    protected void emitResult(MessageContext mc, byte[] output, String outType,
                              String responseVariable, Boolean overwriteBody,
                              String fileName, Date modificationTime) {
        writeResponse(mc, output, outType, responseVariable, overwriteBody,
                literalMetadata(fileName, modificationTime));
    }

    /**
     * Write a verification result: the recovered payload, the signature verdict
     * ({@code attributes.signatureValid}), and any embedded literal-data metadata
     * ({@code fileName} / {@code modificationTime}). Used by verify / decrypt-then-verify.
     */
    protected void emitVerificationResult(MessageContext mc, byte[] output, boolean signatureValid,
                                          String fileName, Date modificationTime, String outType,
                                          String responseVariable, Boolean overwriteBody) {
        Map<String, Object> attributes = literalMetadata(fileName, modificationTime);
        attributes.put(PGPCryptoConstants.ATTR_SIGNATURE_VALID, signatureValid);
        writeResponse(mc, output, outType, responseVariable, overwriteBody, attributes);
    }

    /**
     * Build the response-variable attributes for the embedded literal-data metadata. Only
     * meaningful values are included; the modification time is rendered as an ISO-8601 instant.
     */
    private Map<String, Object> literalMetadata(String fileName, Date modificationTime) {
        Map<String, Object> attributes = new HashMap<>();
        if (fileName != null && !fileName.isEmpty()) {
            attributes.put(PGPCryptoConstants.ATTR_FILE_NAME, fileName);
        }
        if (modificationTime != null) {
            attributes.put(PGPCryptoConstants.ATTR_MODIFICATION_TIME,
                    Instant.ofEpochMilli(modificationTime.getTime()).toString());
        }
        return attributes;
    }

    /**
     * Emit the result via the connector-core {@link #handleConnectorResponse} helper, which builds
     * the {@code {payload, attributes, headers}} response variable and honours {@code overwriteBody}
     * (result → variable payload when false / message body when true). The variable payload is a
     * text-safe string (text for TEXT, base64 otherwise). For the {@code BINARY} carriage with
     * {@code overwriteBody=true} the body is additionally rewritten as raw
     * {@code application/octet-stream} so File connector / VFS write a byte-faithful file.
     */
    private void writeResponse(MessageContext mc, byte[] output, String outType,
                               String responseVariable, Boolean overwriteBody,
                               Map<String, Object> attributes) {
        boolean overwrite = Boolean.TRUE.equals(overwriteBody);
        String payload = PGPCryptoConstants.MSG_TYPE_TEXT.equals(outType)
                ? new String(output, charset(mc))
                : Base64.getEncoder().encodeToString(output);
        Map<String, Object> attrs = attributes != null ? attributes : new HashMap<>();

        if (responseVariable != null) {
            // Populate the response variable {payload, attributes, headers} only. We always pass
            // overwriteBody=false here so the (JSON-oriented) connector-core helper never writes a
            // JSON body; writeBody() below owns any body write in the correct raw carriage. The
            // JsonPrimitive is used because its toString() is always valid JSON, so the helper never
            // fails on our text / base64 payloads.
            handleConnectorResponse(mc, responseVariable, false, new JsonPrimitive(payload),
                    new HashMap<>(), attrs);
        }
        if (overwrite || responseVariable == null) {
            writeBody(mc, output, outType);
        }
    }

    /**
     * Write the output to the message body in the requested carriage: TEXT → text/plain, BASE64 →
     * base64 text/plain, BINARY → raw application/octet-stream (byte-faithful for File connector / VFS).
     */
    private void writeBody(MessageContext mc, byte[] output, String outType) {
        byte[] bytes;
        String contentType;
        if (PGPCryptoConstants.MSG_TYPE_BINARY.equals(outType)) {
            bytes = output;
            contentType = PGPCryptoConstants.CONTENT_TYPE_BINARY;
        } else if (PGPCryptoConstants.MSG_TYPE_BASE64.equals(outType)) {
            bytes = Base64.getEncoder().encodeToString(output).getBytes(StandardCharsets.UTF_8);
            contentType = PGPCryptoConstants.CONTENT_TYPE_TEXT;
        } else {
            bytes = output;
            contentType = PGPCryptoConstants.CONTENT_TYPE_TEXT;
        }
        try {
            PayloadUtils.setContent(axis2Context(mc), new ByteArrayInputStream(bytes), contentType);
        } catch (Exception e) {
            throw new SynapseException("Unable to write the operation output to the message body.", e);
        }
    }

    // Helpers Methods to read parameters from the message context, with optional default values.

    protected String param(MessageContext mc, String name) {
        Object value = getParameter(mc, name);
        if (value == null) {
            return null;
        }
        String str = value.toString();
        return str.isEmpty() ? null : str;
    }

    protected String param(MessageContext mc, String name, String defaultValue) {
        String value = param(mc, name);
        return value == null ? defaultValue : value;
    }

    protected boolean boolParam(MessageContext mc, String name, boolean defaultValue) {
        String value = param(mc, name);
        return value == null ? defaultValue : Boolean.parseBoolean(value.trim());
    }

    // Connection (key store) resolution helpers.

    /**
     * Resolve the public (trust) key store referenced by the given connection-key parameter.
     *
     * @param configKeyParam the operation parameter naming the connection (e.g.
     *                       {@link PGPParameterKey#ENCRYPTION_CONFIG_KEY}).
     * @throws CryptoException if the connection is missing, not initialised, or is a private store.
     */
    protected PgpKeyStore requirePublicStore(MessageContext mc, String configKeyParam) throws CryptoException {
        PgpKeyStore store = resolveStore(mc, configKeyParam);
        if (store.isPrivate()) {
            throw new CryptoException(CryptoError.INVALID_CONFIGURATION,
                    "Connection '" + store.getName() + "' is a private key store; a public key store is required here.");
        }
        return store;
    }

    /**
     * Resolve the private (identity) key store referenced by the given connection-key parameter.
     *
     * @param configKeyParam the operation parameter naming the connection (e.g.
     *                       {@link PGPParameterKey#SIGNING_CONFIG_KEY}).
     * @throws CryptoException if the connection is missing, not initialised, or is a public store.
     */
    protected PgpKeyStore requirePrivateStore(MessageContext mc, String configKeyParam) throws CryptoException {
        PgpKeyStore store = resolveStore(mc, configKeyParam);
        if (!store.isPrivate()) {
            throw new CryptoException(CryptoError.INVALID_CONFIGURATION,
                    "Connection '" + store.getName() + "' is a public key store; a private key store is required here.");
        }
        return store;
    }

    private PgpKeyStore resolveStore(MessageContext mc, String configKeyParam) throws CryptoException {
        String connectionName = param(mc, configKeyParam);
        if (connectionName == null) {
            throw new CryptoException(CryptoError.INVALID_CONFIGURATION,
                    "No key store connection was configured ('" + configKeyParam + "').");
        }
        PgpKeyStore store = PgpKeyStoreHandler.get(connectionName);
        if (store == null) {
            throw new CryptoException(CryptoError.KEY_NOT_FOUND,
                    "PGP key store connection '" + connectionName + "' is not deployed or failed to initialise.");
        }
        return store;
    }

    /** Inbound signer-key trust policy: reject signatures from revoked / expired keys unless disabled. */
    protected boolean requireValidSignerKey(MessageContext mc) {
        return boolParam(mc, PGPParameterKey.REQUIRE_VALID_SIGNER_KEY,
                PGPCryptoConstants.DEFAULT_REQUIRE_VALID_SIGNER_KEY);
    }

    /**
     * Resolve the input carriage ({@code TEXT}/{@code BASE64}/{@code BINARY}) for an <b>outbound</b>
     * operation (encrypt / sign), defaulting as given. This stays an explicit choice on purpose:
     * the input here is arbitrary plaintext, and "is this string literal text or base64?" is
     * undecidable (a base64-encoded file and a plain-text message can both be valid base64), so
     * guessing it would risk silently encrypting the wrong bytes. Inbound operations, where the
     * input is self-describing OpenPGP data, use {@link #readPgpInput} instead.
     */
    protected String inputType(MessageContext mc, String defaultType) {
        return PGPCryptoConstants.resolveMessageType(param(mc, PGPParameterKey.INPUT_TYPE), defaultType);
    }

    /**
     * Read an inbound OpenPGP message (decrypt / verify) as bytes, auto-detecting its carriage.
     *
     * <ul>
     *   <li>If {@code sourceContent} contains the ASCII-armor header ({@code -----BEGIN PGP}), the
     *       armored block is extracted <b>from that header onward</b> and returned as text bytes.
     *       Extracting (rather than just detecting) is essential: the block routinely arrives wrapped
     *       by the transport / message builder — inside a {@code <text>...</text>} payload element or
     *       behind a leading quote — and Bouncy Castle's armor parser fails on any prefix glued to the
     *       header line. Trailing wrapper after {@code -----END ...-----} is ignored by the parser.</li>
     *   <li>Otherwise the content is treated as base64 of a binary OpenPGP message and decoded.</li>
     * </ul>
     *
     * <p>The detection is unambiguous: base64 of binary OpenPGP can never contain the literal
     * {@code -----BEGIN PGP} (base64 has no {@code -}).</p>
     */
    protected byte[] readPgpInput(MessageContext mc) throws CryptoException {
        if (!readsFromExpression(mc)) {
            // Message-body source: read the raw OpenPGP bytes directly.
            // Bouncy Castle's decoder handles both armored and binary; no further processing needed.
            return readMessageBodyBytes(mc);
        }
        String content = requireSourceContent(mc);
        int armorAt = content.indexOf(PGPCryptoConstants.ARMOR_HEADER_PREFIX);
        if (armorAt >= 0) {
            return content.substring(armorAt).getBytes(charset(mc));
        }
        try {
            return Base64.getMimeDecoder().decode(content.trim());
        } catch (IllegalArgumentException e) {
            throw new CryptoException(CryptoError.INVALID_INPUT,
                    "Input is not a PGP message: no ASCII-armor header found and it is not valid base64 "
                    + "of a binary OpenPGP message.", e);
        }
    }

    /**
     * Read the raw message-body bytes directly from the Axis2 message context, bypassing the
     * {@code sourceContent} String expression. Used when no {@code sourceContent} is configured, so a
     * binary payload (e.g. a file read as {@code application/octet-stream}) reaches the crypto
     * operation byte-faithfully rather than being mangled through a base64 String by {@code ${payload}}.
     *
     * <p>Handling by payload shape: a binary payload backed by a {@link DataHandler} yields its raw
     * bytes; a {@code <binary>} wrapper carrying base64 text is base64-decoded; any other text payload
     * is taken as literal text. This keeps file/binary flows correct while leaving text/HTTP flows
     * (and explicit {@code sourceContent} expressions) on their existing paths.</p>
     */
    protected byte[] readMessageBodyBytes(MessageContext mc) throws CryptoException {
        org.apache.axis2.context.MessageContext axis2 = axis2Context(mc);
        OMElement body = (axis2.getEnvelope() != null && axis2.getEnvelope().getBody() != null)
                ? axis2.getEnvelope().getBody().getFirstElement() : null;
        if (body == null) {
            throw new CryptoException(CryptoError.INVALID_INPUT,
                    "No message body found to process (and no 'sourceContent' was configured).");
        }
        OMNode child = body.getFirstOMChild();
        if (child instanceof OMText) {
            OMText text = (OMText) child;
            Object dataHandler = text.getDataHandler();
            if (text.isBinary() && dataHandler instanceof DataHandler) {
                try (InputStream in = ((DataHandler) dataHandler).getInputStream()) {
                    return readFully(in);
                } catch (IOException e) {
                    throw new CryptoException(CryptoError.INVALID_INPUT,
                            "Failed to read the binary message body.", e);
                }
            }
            String value = text.getText() == null ? "" : text.getText();
            // A <binary> wrapper carries base64 text; any other text wrapper carries literal text.
            if ("binary".equalsIgnoreCase(body.getLocalName())) {
                try {
                    return Base64.getMimeDecoder().decode(value.trim());
                } catch (IllegalArgumentException e) {
                    throw new CryptoException(CryptoError.INVALID_INPUT,
                            "Binary message body is not valid base64.", e);
                }
            }
            return value.getBytes(charset(mc));
        }
        // Non-text body (e.g. an XML / JSON element): serialise it to bytes.
        return body.toString().getBytes(charset(mc));
    }

    private static byte[] readFully(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) >= 0) {
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }

    /**
     * Resolve the output carriage for an <b>outbound</b> operation (encrypt / sign / signAndEncrypt).
     * The output shape is decided solely by {@code armor}: armored output is ASCII text ({@code TEXT}),
     * non-armored output is raw binary ({@code BINARY}). There is deliberately no separate BASE64
     * option — armored already provides a standard text-safe format, and binary output is still
     * surfaced as base64 in the response variable for HTTP/JSON consumers.
     */
    protected String outboundOutputType(MessageContext mc, boolean armor) {
        return armor ? PGPCryptoConstants.MSG_TYPE_TEXT : PGPCryptoConstants.MSG_TYPE_BINARY;
    }

    /**
     * Resolve the output carriage for an <b>inbound</b> operation (decrypt / verify). An explicit
     * {@code outputType} always wins; otherwise the carriage defaults from the OpenPGP literal-data
     * format byte recovered from the message — binary-tagged payloads default to {@code BINARY} (raw,
     * byte-faithful) and text-tagged payloads to {@code TEXT}. This lets a connector-to-connector
     * exchange round-trip binary vs. text with no manual {@code outputType} configuration, while a
     * third-party sender that always tags binary can still be overridden explicitly.
     */
    protected String inboundOutputType(MessageContext mc, boolean binaryFormat) {
        String explicit = param(mc, PGPParameterKey.OUTPUT_TYPE);
        if (explicit != null) {
            return PGPCryptoConstants.resolveMessageType(explicit, PGPCryptoConstants.MSG_TYPE_TEXT);
        }
        return binaryFormat ? PGPCryptoConstants.MSG_TYPE_BINARY : PGPCryptoConstants.MSG_TYPE_TEXT;
    }

    private Charset charset(MessageContext mc) {
        return Charset.forName(param(mc, PGPParameterKey.CHARSET, PGPCryptoConstants.DEFAULT_CHARSET));
    }

    /** The Axis2 message context, used for raw {@code application/octet-stream} body writes. */
    private static org.apache.axis2.context.MessageContext axis2Context(MessageContext mc) {
        return ((Axis2MessageContext) mc).getAxis2MessageContext();
    }
}
