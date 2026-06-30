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

import org.apache.synapse.ManagedLifecycle;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.SynapseEnvironment;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.wso2.carbon.connector.cryptography.exception.CryptoException;
import org.wso2.carbon.connector.cryptography.pgp.constant.PGPParameterKey;
import org.wso2.carbon.connector.cryptography.pgp.util.PGPKeyUtils;
import org.wso2.integration.connector.core.AbstractConnector;

/**
 * Initialises a PGP key store connection and registers it with {@link PgpKeyStoreHandler}.
 *
 * <p>This is the {@code init} operation behind both connection types. It reads the connection
 * parameters, resolves the configured key location (registry / environment / inline / filesystem)
 * and parses it once into a Bouncy Castle key-ring collection, then stores that immutable
 * collection on a named {@link PgpKeyStore} for the operations to reuse:</p>
 *
 * <ul>
 *   <li>{@link PgpKeyStore#TYPE_PRIVATE} — parses the secret key ring and keeps the default passphrase.</li>
 *   <li>{@link PgpKeyStore#TYPE_PUBLIC} — parses the public key ring.</li>
 * </ul>
 */
public class PgpKeyStoreInit extends AbstractConnector implements ManagedLifecycle {

    /** The connection this init instance registered, so {@link #destroy()} can unregister it on undeploy. */
    private volatile String connectionName;

    @Override
    public void connect(MessageContext messageContext) {
        String name = stringParam(messageContext, PGPParameterKey.CONNECTION_NAME);
        String connectionType = stringParam(messageContext, PGPParameterKey.CONNECTION_TYPE);
        if (name == null) {
            handleException("PGP key store connection requires a 'connectionName'.", messageContext);
        }
        this.connectionName = name;
        String keyIdentifier = stringParam(messageContext, PGPParameterKey.KEY_IDENTIFIER);
        try {
            if (PgpKeyStore.TYPE_PRIVATE.equals(connectionType)) {
                String privateKeyPath = stringParam(messageContext, PGPParameterKey.PRIVATE_KEY_PATH);
                String passphrase = stringParam(messageContext, PGPParameterKey.PASSPHRASE);
                PGPSecretKeyRingCollection secretKeys =
                        PGPKeyUtils.loadSecretKeyRingCollection(messageContext, privateKeyPath);
                PgpKeyStoreHandler.add(
                        PgpKeyStore.privateStore(name, keyIdentifier, secretKeys, passphrase));
            } else if (PgpKeyStore.TYPE_PUBLIC.equals(connectionType)) {
                String publicKeyPath = stringParam(messageContext, PGPParameterKey.PUBLIC_KEY_PATH);
                PGPPublicKeyRingCollection publicKeys =
                        PGPKeyUtils.loadPublicKeyRingCollection(messageContext, publicKeyPath);
                PgpKeyStoreHandler.add(
                        PgpKeyStore.publicStore(name, keyIdentifier, publicKeys));
            } else {
                handleException("Unknown PGP key store connection type: " + connectionType, messageContext);
            }
        } catch (CryptoException e) {
            handleException("Failed to initialise PGP key store connection '" + name + "': "
                    + e.getMessage(), e, messageContext);
        }
        // The passphrase is held only on the registered PgpKeyStore for the connection's lifetime; it
        // is read from a template parameter (not a message property), so there is nothing to scrub here.
    }

    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        // No environment-scoped state to initialise.
    }

    @Override
    public void destroy() {
        // Unregister this connection's key store when the connection is undeployed.
        PgpKeyStoreHandler.remove(connectionName);
    }

    private String stringParam(MessageContext messageContext, String name) {
        Object value = getParameter(messageContext, name);
        if (value == null) {
            return null;
        }
        String str = value.toString().trim();
        return str.isEmpty() ? null : str;
    }
}
