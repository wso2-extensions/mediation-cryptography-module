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
package org.wso2.carbon.connector.cryptography.exception;

/**
 * Thrown when a cryptographic operation fails. Carries a clear message for the mediation fault
 * sequence without leaking key material, plus a {@link CryptoError} that maps to the module's
 * {@code 7013xx} error code surfaced as the synapse {@code ERROR_CODE} / {@code ERROR_MESSAGE}.
 *
 * <p>Always constructed with an explicit {@link CryptoError} so the operation reports a precise,
 * branchable code to the mediation fault sequence.</p>
 */
public class CryptoException extends Exception {

    private final CryptoError error;

    public CryptoException(CryptoError error, String message) {
        super(message);
        this.error = error;
    }

    public CryptoException(CryptoError error, String message, Throwable cause) {
        super(message, cause);
        this.error = error;
    }

    /** @return the error classification for this failure. */
    public CryptoError getError() {
        return error;
    }
}
