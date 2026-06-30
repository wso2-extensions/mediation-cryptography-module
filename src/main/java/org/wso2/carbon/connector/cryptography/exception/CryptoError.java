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
 * Error codes and tags surfaced by the cryptography module's operations.
 *
 * <p>The codes follow the WSO2 connector/module convention: six digits, beginning with
 * {@code 7}; the {@code 7013xx} block is allocated to this (cryptography) module, and the last
 * two digits identify the specific error. The tag (e.g. {@code CRYPTO:KEY_NOT_FOUND}) is the
 * human-readable form set as the synapse {@code ERROR_MESSAGE} so a fault sequence can branch on
 * it. All errors share the single {@code CRYPTO:} prefix expected from one connector.</p>
 *
 * <p>To categorize further as more cryptography families are added, reserve numeric sub-ranges
 * within this block rather than introducing family-specific tag prefixes: {@code 701301}–
 * {@code 701319} are the common errors below; {@code 701320}–{@code 701339} can be reserved for
 * PGP-specific errors and {@code 701340}+ for AES-specific ones, all kept in this enum under the
 * same {@code CRYPTO:} prefix.</p>
 */
public enum CryptoError {

    /** Input is missing or not valid for the declared carriage (e.g. malformed base64). */
    INVALID_INPUT("701301", "CRYPTO:INVALID_INPUT"),
    /** An unsupported algorithm name or an otherwise invalid parameter value was supplied. */
    INVALID_CONFIGURATION("701302", "CRYPTO:INVALID_CONFIGURATION"),
    /** A required key is absent: key file missing, or no matching / capability-bearing key found. */
    KEY_NOT_FOUND("701303", "CRYPTO:KEY_NOT_FOUND"),
    /** A key-ring file could not be read or parsed. */
    KEY_LOAD_ERROR("701304", "CRYPTO:KEY_LOAD_ERROR"),
    /** The private key could not be unlocked (wrong passphrase). */
    INVALID_PASSPHRASE("701305", "CRYPTO:INVALID_PASSPHRASE"),
    /** The input is not a valid message (not encrypted / not signed, or malformed). */
    INVALID_MESSAGE_FORMAT("701306", "CRYPTO:INVALID_MESSAGE_FORMAT"),
    /** Integrity-protection (MDC) verification failed — the message may have been tampered with. */
    INTEGRITY_CHECK_FAILED("701307", "CRYPTO:INTEGRITY_CHECK_FAILED"),
    /** The message carried no integrity-protection (MDC) packet and {@code requireIntegrity} is on. */
    INTEGRITY_PROTECTION_MISSING("701308", "CRYPTO:INTEGRITY_PROTECTION_MISSING"),
    /** An encrypt / decrypt / sign / verify processing step failed. */
    OPERATION_ERROR("701309", "CRYPTO:OPERATION_ERROR"),
    /** An unexpected error not covered by the more specific codes above. */
    GENERAL_ERROR("701310", "CRYPTO:GENERAL_ERROR"),

    // ---- PGP-specific errors (701320+) ----
    /** The selected key exists but cannot be used: it is revoked or has expired. */
    KEY_UNUSABLE("701320", "CRYPTO:KEY_UNUSABLE"),
    /** The signature verified cryptographically but the signer's key is untrusted (revoked / expired). */
    SIGNER_KEY_UNTRUSTED("701321", "CRYPTO:SIGNER_KEY_UNTRUSTED");

    private final String code;
    private final String message;

    CryptoError(String code, String message) {
        this.code = code;
        this.message = message;
    }

    /** @return the six-digit error code (e.g. {@code 701303}). */
    public String getErrorCode() {
        return code;
    }

    /** @return the error tag (e.g. {@code CRYPTO:KEY_NOT_FOUND}). */
    public String getErrorMessage() {
        return message;
    }
}
