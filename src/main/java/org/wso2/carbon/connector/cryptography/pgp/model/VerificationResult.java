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

import java.util.Date;

/**
 * Result of a verification: the recovered payload (with any embedded literal-data metadata) and
 * whether the signature checked out. Returned by the verify and decrypt-then-verify operations.
 */
public final class VerificationResult {

    private final LiteralData literalData;
    private final boolean valid;

    /**
     * @param literalData the recovered payload and its embedded metadata.
     * @param valid       whether the signature verified successfully.
     */
    public VerificationResult(LiteralData literalData, boolean valid) {
        this.literalData = literalData;
        this.valid = valid;
    }

    /** @return the recovered (decrypted / verified) payload bytes. */
    public byte[] getData() {
        return literalData.getData();
    }

    /** @return the embedded original file name, or {@code null} when not meaningfully set. */
    public String getFileName() {
        return literalData.getFileName();
    }

    /** @return the embedded modification time, or {@code null} when not meaningfully set. */
    public Date getModificationTime() {
        return literalData.getModificationTime();
    }

    /** @return {@code true} when the sender tagged the payload as binary; see {@link LiteralData#isBinaryFormat()}. */
    public boolean isBinaryFormat() {
        return literalData.isBinaryFormat();
    }

    /** @return {@code true} if the signature verified against the supplied public keys. */
    public boolean isValid() {
        return valid;
    }
}
