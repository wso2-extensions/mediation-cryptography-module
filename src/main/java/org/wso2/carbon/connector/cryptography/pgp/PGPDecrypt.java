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

import org.wso2.carbon.connector.cryptography.exception.CryptoException;
import org.wso2.carbon.connector.cryptography.pgp.connection.PgpKeyStore;
import org.wso2.carbon.connector.cryptography.pgp.constant.PGPCryptoConstants;
import org.wso2.carbon.connector.cryptography.pgp.constant.PGPParameterKey;
import org.wso2.carbon.connector.cryptography.pgp.model.LiteralData;
import org.wso2.carbon.connector.cryptography.pgp.util.PGPCryptoUtils;
import org.apache.synapse.MessageContext;

/**
 * Decrypts the input payload using your private key and passphrase (confidentiality).
 */
public class PGPDecrypt extends AbstractPGPOperation {

    @Override
    protected void executePgp(MessageContext mc, String responseVariable, Boolean overwriteBody)
            throws CryptoException {
        // Inbound: armored block is extracted from the content; otherwise treated as base64 binary.
        byte[] input = readPgpInput(mc);

        PgpKeyStore decryptionStore = requirePrivateStore(mc, PGPParameterKey.DECRYPTION_CONFIG_KEY);
        String passphrase = decryptionStore.getPassphrase();
        boolean requireIntegrity = boolParam(mc, PGPParameterKey.REQUIRE_INTEGRITY,
                PGPCryptoConstants.DEFAULT_REQUIRE_INTEGRITY);

        LiteralData result = PGPCryptoUtils.decrypt(input, decryptionStore.getSecretKeys(), passphrase, requireIntegrity);

        emitResult(mc, result.getData(), inboundOutputType(mc, result.isBinaryFormat()),
                responseVariable, overwriteBody, result.getFileName(), result.getModificationTime());
    }

    @Override
    protected String operationName() {
        return "decrypt";
    }
}
