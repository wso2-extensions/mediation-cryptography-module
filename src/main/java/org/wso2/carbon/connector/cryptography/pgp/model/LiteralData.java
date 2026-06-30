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
 * The contents of an OpenPGP literal-data packet recovered on decrypt / verify: the payload
 * bytes plus the metadata OpenPGP embeds alongside it — the original file name, a modification
 * time, and the format byte ({@code 'b'} binary, {@code 't'} text, {@code 'u'} UTF-8 text).
 *
 * <p>The file name and modification time are informational only (surfaced to the mediation through
 * the response variable's attributes). The format byte is used as a hint to default the inbound
 * output carriage (binary vs. text) when the operation was not given an explicit {@code outputType}.</p>
 */
public final class LiteralData {

    /** OpenPGP literal-data format byte for binary content ({@code PGPLiteralData.BINARY}). */
    private static final char FORMAT_BINARY = 'b';

    private final byte[] data;
    private final String fileName;
    private final Date modificationTime;
    private final char format;

    /**
     * @param data             the recovered payload bytes.
     * @param fileName         the embedded file name, or {@code null} when absent / the
     *                         {@code _CONSOLE} sentinel.
     * @param modificationTime the embedded modification time, or {@code null} when absent / epoch.
     * @param format           the OpenPGP literal-data format byte ({@code 'b'} / {@code 't'} / {@code 'u'}).
     */
    public LiteralData(byte[] data, String fileName, Date modificationTime, char format) {
        this.data = data;
        this.fileName = fileName;
        this.modificationTime = modificationTime == null ? null : new Date(modificationTime.getTime());
        this.format = format;
    }

    /** @return the recovered payload bytes. */
    public byte[] getData() {
        return data;
    }

    /**
     * @return {@code true} when the sender tagged the payload as binary ({@code 'b'}); {@code false}
     * for the text formats ({@code 't'} / {@code 'u'}). Used to default the inbound output carriage.
     */
    public boolean isBinaryFormat() {
        return format == FORMAT_BINARY;
    }

    /** @return the embedded original file name, or {@code null} when not meaningfully set. */
    public String getFileName() {
        return fileName;
    }

    /** @return the embedded modification time, or {@code null} when not meaningfully set. */
    public Date getModificationTime() {
        return modificationTime == null ? null : new Date(modificationTime.getTime());
    }
}
