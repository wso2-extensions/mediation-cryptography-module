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
package org.wso2.carbon.connector.cryptography.pgp.connection;

import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.wso2.carbon.connector.cryptography.pgp.model.KeySelector;

/**
 * A reusable, named PGP key store resolved once when its connection is initialised and then shared,
 * read-only, across mediation threads. Two kinds exist, matching the two connection types exposed
 * to the low-code editor:
 *
 * <ul>
 *   <li><b>{@link #TYPE_PRIVATE}</b> — your own identity: a parsed secret key-ring collection plus a
 *       default passphrase. Used by sign / decrypt.</li>
 *   <li><b>{@link #TYPE_PUBLIC}</b> — a trust store of external parties' public keys: a parsed public
 *       key-ring collection. Used by encrypt / verify.</li>
 * </ul>
 *
 * <p>Holding the already-parsed Bouncy Castle collections on the connection means the key ring is
 * parsed once at connection-init time rather than on every message, and lets private and public key
 * material live in separate, independently-rotated stores.</p>
 */
public final class PgpKeyStore {

    /** Connection type name for a private (secret) key store; must match the connection uischema. */
    public static final String TYPE_PRIVATE = "PGP_PRIVATE_KEY";
    /** Connection type name for a public (trust) key store; must match the connection uischema. */
    public static final String TYPE_PUBLIC = "PGP_PUBLIC_KEY";

    private final String name;
    private final String type;
    private final String keyIdentifier;
    private final PGPPublicKeyRingCollection publicKeys;
    private final PGPSecretKeyRingCollection secretKeys;
    private final String passphrase;

    private PgpKeyStore(String name, String type, String keyIdentifier,
                        PGPPublicKeyRingCollection publicKeys,
                        PGPSecretKeyRingCollection secretKeys, String passphrase) {
        this.name = name;
        this.type = type;
        this.keyIdentifier = keyIdentifier;
        this.publicKeys = publicKeys;
        this.secretKeys = secretKeys;
        this.passphrase = passphrase;
    }

    /** Build a public (trust) key store: a parsed public key-ring plus the bound key identifier. */
    public static PgpKeyStore publicStore(String name, String keyIdentifier,
                                          PGPPublicKeyRingCollection publicKeys) {
        return new PgpKeyStore(name, TYPE_PUBLIC, keyIdentifier, publicKeys, null, null);
    }

    /** Build a private (identity) key store: a parsed secret key-ring, bound key identifier, passphrase. */
    public static PgpKeyStore privateStore(String name, String keyIdentifier,
                                           PGPSecretKeyRingCollection secretKeys, String passphrase) {
        return new PgpKeyStore(name, TYPE_PRIVATE, keyIdentifier, null, secretKeys, passphrase);
    }

    public String getName() {
        return name;
    }

    public boolean isPrivate() {
        return TYPE_PRIVATE.equals(type);
    }

    /**
     * The key selector derived from this connection's bound identifier. Empty when no identifier is
     * configured (valid for decrypt / verify, which match the key from the message; encrypt / sign
     * enforce a non-empty selector via {@link KeySelector#requireStrictSelector()}).
     */
    public KeySelector getSelector() {
        return KeySelector.of(keyIdentifier);
    }

    /** @return the parsed public key-ring collection, or {@code null} for a private store. */
    public PGPPublicKeyRingCollection getPublicKeys() {
        return publicKeys;
    }

    /** @return the parsed secret key-ring collection, or {@code null} for a public store. */
    public PGPSecretKeyRingCollection getSecretKeys() {
        return secretKeys;
    }

    /** @return the default passphrase configured on a private store; {@code null} otherwise. */
    public String getPassphrase() {
        return passphrase;
    }
}
