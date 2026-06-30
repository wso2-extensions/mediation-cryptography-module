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
package org.wso2.carbon.connector.cryptography.pgp.model;

/**
 * How a caller pins a key inside a key ring. Three unambiguous selectors are supported, tried in
 * precedence order:
 *
 * <ol>
 *   <li><b>{@code fingerprint}</b> — a full key fingerprint (32 hex for v3, 40 for v4, 64 for
 *       v5/v6). The most precise selector; matched by exact byte comparison.</li>
 *   <li><b>{@code keyId}</b> — a 64-bit OpenPGP Key ID as a 16-character hex string
 *       (e.g. {@code 0x7B9E1A2C3D4E5F6A}); matched as an exact unsigned-long Key ID.</li>
 *   <li><b>{@code userId}</b> — a user ID or e-mail, matched <em>exactly</em> and case-insensitively
 *       against either the full OpenPGP user-ID string ({@code "Alice <alice@example.com>"}) or the
 *       e-mail inside its angle brackets ({@code "alice@example.com"}). This is a usability selector
 *       for integrators who know a partner's e-mail rather than its fingerprint.</li>
 * </ol>
 *
 * <p>The match is exact, not a substring: the legacy substring user-ID match (prone to collisions
 * and key-spoofing) is not reinstated. A fingerprint or Key ID may point at a certificate's primary
 * key; when that key lacks the required capability (encryption is typically on a subkey) resolution
 * falls back to the matching capability key within the same certificate.</p>
 */
public final class KeySelector {

    private final String fingerprint;
    private final String keyId;
    private final String userId;

    public KeySelector(String fingerprint, String keyId, String userId) {
        this.fingerprint = blankToNull(fingerprint);
        this.keyId = blankToNull(keyId);
        this.userId = blankToNull(userId);
    }

    /**
     * Build a selector from a single, user-supplied identifier, auto-routing by its shape so the
     * caller need not decide "fingerprint, Key ID or user ID?":
     *
     * <ul>
     *   <li>an all-hex value of length 32 / 40 / 64 (after stripping {@code 0x}, spaces, colons)
     *       &rarr; fingerprint match;</li>
     *   <li>any other all-hex value (notably a 16-hex 64-bit Key ID) &rarr; Key ID match;</li>
     *   <li>anything containing non-hex characters (e.g. an e-mail or name) &rarr; exact user-ID match.</li>
     * </ul>
     *
     * <p>A blank identifier yields an empty selector (see {@link #requireStrictSelector()}).</p>
     */
    public static KeySelector of(String identifier) {
        String value = blankToNull(identifier);
        if (value == null) {
            return new KeySelector(null, null, null);
        }
        String clean = value.replaceAll("(?i)0x|\\s+|:", "");
        if (clean.matches("[0-9a-fA-F]+")) {
            int len = clean.length();
            if (len == 32 || len == 40 || len == 64) {
                return new KeySelector(value, null, null);
            }
            return new KeySelector(null, value, null);
        }
        return new KeySelector(null, null, value);
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public String getKeyId() {
        return keyId;
    }

    public String getUserId() {
        return userId;
    }

    /** @return {@code true} when no selector (fingerprint, Key ID or user ID) was supplied. */
    public boolean isEmpty() {
        return fingerprint == null && keyId == null && userId == null;
    }

    /**
     * Ensure a selector was supplied. Precedence is fingerprint, then Key ID, then user ID;
     * supplying none is a configuration error.
     *
     * @throws IllegalArgumentException if no selector is present.
     */
    public void requireStrictSelector() {
        if (isEmpty()) {
            throw new IllegalArgumentException(
                    "You must provide a key identifier to select the PGP key: a fingerprint, "
                    + "a 16-hex Key ID, or an exact user ID / e-mail.");
        }
    }

    /** Human-readable rendering of this selector for error messages. */
    public String describe() {
        if (fingerprint != null) {
            return "fingerprint '" + fingerprint + "'";
        }
        if (keyId != null) {
            return "key ID '" + keyId + "'";
        }
        if (userId != null) {
            return "user ID '" + userId + "'";
        }
        return "no selector";
    }

    private static String blankToNull(String value) {
        return (value == null || value.trim().isEmpty()) ? null : value.trim();
    }
}
