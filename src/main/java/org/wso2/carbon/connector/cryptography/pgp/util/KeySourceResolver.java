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

import org.apache.axiom.om.OMNode;
import org.apache.axiom.om.OMText;
import org.apache.synapse.MessageContext;
import org.apache.synapse.registry.Registry;
import org.wso2.carbon.connector.cryptography.exception.CryptoError;
import org.wso2.carbon.connector.cryptography.exception.CryptoException;
import org.wso2.carbon.connector.cryptography.pgp.constant.PGPCryptoConstants;

import javax.activation.DataHandler;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Resolves a configured key location string to the raw key-material bytes, decoupling the module
 * from absolute filesystem paths so it fits containerised (Kubernetes) deployments.
 *
 * <p>The location is dispatched by protocol prefix / shape:</p>
 * <ul>
 *   <li>{@code gov:/...}, {@code conf:/...} or {@code resources:...} &rarr; a resource pulled from the
 *       <b>WSO2 Registry</b> (governance / configuration / MI project resources) via the Synapse
 *       registry API.</li>
 *   <li>{@code env:NAME} &rarr; the value of the <b>environment variable</b> {@code NAME}
 *       (e.g. a key injected into a pod from a Kubernetes Secret).</li>
 *   <li>An input that contains the ASCII-armor header ({@code -----BEGIN PGP ...}) &rarr; the string
 *       itself is treated as the <b>inline key content</b> (a payload / variable carrying the key).</li>
 *   <li>Anything else &rarr; a <b>filesystem</b> path (the legacy fallback).</li>
 * </ul>
 *
 * <p>{@link #read(MessageContext, String)} performs the actual I/O, resolving the source to raw
 * key-material bytes. It is invoked once per connection at init time.</p>
 */
final class KeySourceResolver {

    private static final String REGISTRY_GOV_PREFIX = "gov:/";
    private static final String REGISTRY_CONF_PREFIX = "conf:/";
    private static final String REGISTRY_RESOURCES_PREFIX = "resources:";
    private static final String ENV_PREFIX = "env:";

    private static final int BUFFER_SIZE = 8192;

    private KeySourceResolver() {
    }

    /** The resolved source kinds, in dispatch precedence order. */
    private enum Kind {
        REGISTRY, ENV, INLINE, FILE
    }

    /**
     * Read the raw key-material bytes for {@code source}. The returned bytes may be ASCII-armored or
     * binary OpenPGP; the caller wraps them in {@link org.bouncycastle.openpgp.PGPUtil#getDecoderStream}
     * which transparently handles both.
     */
    static byte[] read(MessageContext mc, String source) throws CryptoException {
        String trimmed = requireNonBlank(source);
        switch (classify(trimmed)) {
            case REGISTRY:
                return readFromRegistry(mc, trimmed);
            case ENV:
                return readFromEnvironment(trimmed);
            case INLINE:
                return trimmed.getBytes(StandardCharsets.UTF_8);
            case FILE:
            default:
                return readFromFile(trimmed);
        }
    }

    private static Kind classify(String source) {
        String lower = source.toLowerCase(Locale.ENGLISH);
        if (lower.startsWith(REGISTRY_GOV_PREFIX) || lower.startsWith(REGISTRY_CONF_PREFIX)
                || lower.startsWith(REGISTRY_RESOURCES_PREFIX)) {
            return Kind.REGISTRY;
        }
        if (lower.startsWith(ENV_PREFIX)) {
            return Kind.ENV;
        }
        if (source.contains(PGPCryptoConstants.ARMOR_HEADER_PREFIX)) {
            return Kind.INLINE;
        }
        return Kind.FILE;
    }

    // Key Source Readers

    private static byte[] readFromRegistry(MessageContext mc, String key) throws CryptoException {
        if (mc == null || mc.getConfiguration() == null) {
            throw new CryptoException(CryptoError.KEY_LOAD_ERROR,
                    "Registry key source '" + key + "' requires a message context but none was available.");
        }
        Registry registry = mc.getConfiguration().getRegistry();
        if (registry == null) {
            throw new CryptoException(CryptoError.KEY_LOAD_ERROR,
                    "No WSO2 Registry is configured; cannot resolve key source: " + key);
        }
        OMNode node = registry.lookup(key);
        if (node == null) {
            throw new CryptoException(CryptoError.KEY_NOT_FOUND,
                    "Registry resource not found: " + key);
        }
        try {
            if (node instanceof OMText) {
                OMText text = (OMText) node;
                if (text.isBinary()) {
                    Object dataHandler = text.getDataHandler();
                    if (dataHandler instanceof DataHandler) {
                        try (InputStream in = ((DataHandler) dataHandler).getInputStream()) {
                            return readFully(in);
                        }
                    }
                }
                return text.getText().getBytes(StandardCharsets.UTF_8);
            }
            // A resource stored as XML (unusual for key material) — serialise it back to bytes.
            return node.toString().getBytes(StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new CryptoException(CryptoError.KEY_LOAD_ERROR,
                    "Failed to read registry resource: " + key, e);
        }
    }

    private static byte[] readFromEnvironment(String source) throws CryptoException {
        String name = source.substring(ENV_PREFIX.length()).trim();
        if (name.isEmpty()) {
            throw new CryptoException(CryptoError.INVALID_CONFIGURATION,
                    "Environment key source is missing a variable name (expected 'env:NAME').");
        }
        String value = System.getenv(name);
        if (value == null || value.isEmpty()) {
            throw new CryptoException(CryptoError.KEY_NOT_FOUND,
                    "Environment variable '" + name + "' is not set or is empty.");
        }
        // The variable value is the key material itself (typically an ASCII-armored block injected
        // from a Kubernetes Secret).
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] readFromFile(String source) throws CryptoException {
        File file = new File(normalizeFilePath(source));
        if (!file.exists() || !file.isFile()) {
            throw new CryptoException(CryptoError.KEY_NOT_FOUND, "Key file does not exist: " + file.getPath());
        }
        try (InputStream in = new FileInputStream(file)) {
            return readFully(in);
        } catch (IOException e) {
            throw new CryptoException(CryptoError.KEY_LOAD_ERROR, "Failed to read key file: " + file.getPath(), e);
        }
    }

    // Helpers Methods

    private static String normalizeFilePath(String path) {
        return path.replace('\\', File.separatorChar).replace('/', File.separatorChar);
    }

    private static byte[] readFully(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[BUFFER_SIZE];
        int read;
        while ((read = in.read(buffer)) >= 0) {
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }

    private static String requireNonBlank(String source) throws CryptoException {
        if (source == null || source.trim().isEmpty()) {
            throw new CryptoException(CryptoError.INVALID_CONFIGURATION, "Key source is not configured.");
        }
        return source.trim();
    }
}
