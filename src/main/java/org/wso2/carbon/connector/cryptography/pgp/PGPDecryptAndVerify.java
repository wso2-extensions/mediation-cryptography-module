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
import org.wso2.carbon.connector.cryptography.pgp.model.VerificationResult;
import org.wso2.carbon.connector.cryptography.pgp.util.PGPCryptoUtils;
import org.apache.synapse.MessageContext;

/**
 * Inbound combined operation: decrypt the payload with your private key, then verify the
 * sender's signature with their public key. The recovered payload is emitted through the response
 * variable (or the message body when {@code overwriteBody} is set) and the {@code signatureValid}
 * attribute carries the verification result.
 */
public class PGPDecryptAndVerify extends AbstractPGPOperation {

    @Override
    protected void executePgp(MessageContext mc, String responseVariable, Boolean overwriteBody)
            throws CryptoException {
        // Inbound: armored block is extracted from the content; otherwise treated as base64 binary.
        byte[] input = readPgpInput(mc);

        // Decryption inputs (Receiver side) — private key store
        PgpKeyStore decryptionStore = requirePrivateStore(mc, PGPParameterKey.DECRYPTION_CONFIG_KEY);
        String passphrase = decryptionStore.getPassphrase();
        boolean requireIntegrity = boolParam(mc, PGPParameterKey.REQUIRE_INTEGRITY,
                PGPCryptoConstants.DEFAULT_REQUIRE_INTEGRITY);

        // Verification inputs (Sender side) — public key store
        PgpKeyStore verificationStore = requirePublicStore(mc, PGPParameterKey.VERIFICATION_CONFIG_KEY);

        VerificationResult result = PGPCryptoUtils.decryptAndVerify(input,
                decryptionStore.getSecretKeys(), verificationStore.getPublicKeys(),
                passphrase, requireIntegrity, requireValidSignerKey(mc));

        emitVerificationResult(mc, result.getData(), result.isValid(),
                result.getFileName(), result.getModificationTime(),
                inboundOutputType(mc, result.isBinaryFormat()), responseVariable, overwriteBody);
    }

    @Override
    protected String operationName() {
        return "decryptAndVerify";
    }
}
