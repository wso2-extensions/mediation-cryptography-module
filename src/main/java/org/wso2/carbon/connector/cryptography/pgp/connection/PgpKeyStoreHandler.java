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

import java.util.concurrent.ConcurrentHashMap;

/**
 * Process-wide registry of initialised {@link PgpKeyStore} connections, keyed by connection name.
 *
 * <p>A key store is registered once when its connection ({@code init} operation) is deployed and is
 * then looked up by name from each PGP operation. This mirrors the connection model used by other
 * WSO2 MI modules: the connection owns the resolved, immutable key material and the operations are
 * stateless consumers.</p>
 */
public final class PgpKeyStoreHandler {

    private static final ConcurrentHashMap<String, PgpKeyStore> STORES = new ConcurrentHashMap<>();

    private PgpKeyStoreHandler() {
    }

    /** Register (or replace) a key store under its connection name. */
    public static void add(PgpKeyStore store) {
        STORES.put(store.getName(), store);
    }

    /** @return the key store registered under {@code connectionName}, or {@code null} if none. */
    public static PgpKeyStore get(String connectionName) {
        return connectionName == null ? null : STORES.get(connectionName);
    }

    /** Remove a single key store when its connection is undeployed (see {@code PgpKeyStoreInit.destroy}). */
    public static void remove(String connectionName) {
        if (connectionName != null) {
            STORES.remove(connectionName);
        }
    }
}
