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

import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.wso2.carbon.connector.cryptography.exception.CryptoException;
import org.wso2.carbon.connector.cryptography.pgp.connection.PgpKeyStore;
import org.wso2.carbon.connector.cryptography.pgp.constant.PGPParameterKey;
import org.wso2.carbon.connector.cryptography.pgp.model.VerificationResult;
import org.wso2.carbon.connector.cryptography.pgp.util.PGPCryptoUtils;
import org.apache.synapse.MessageContext;

/**
 * Verifies a signed payload with the sender's public key (authenticity, integrity).
 *
 * <p>The recovered payload is emitted through the response variable (or the message body when
 * {@code overwriteBody} is set) and the {@code signatureValid} attribute carries the verdict so
 * the mediation can branch (process when valid, quarantine when invalid).</p>
 */
public class PGPVerify extends AbstractPGPOperation {

    @Override
    protected void executePgp(MessageContext mc, String responseVariable, Boolean overwriteBody)
            throws CryptoException {
        // Inbound: armored block is extracted from the content; otherwise treated as base64 binary.
        byte[] input = readPgpInput(mc);

        PgpKeyStore verificationStore = requirePublicStore(mc, PGPParameterKey.VERIFICATION_CONFIG_KEY);

        PGPPublicKeyRingCollection publicKeys = verificationStore.getPublicKeys();
        VerificationResult result = PGPCryptoUtils.verify(input, publicKeys, requireValidSignerKey(mc));

        emitVerificationResult(mc, result.getData(), result.isValid(),
                result.getFileName(), result.getModificationTime(),
                inboundOutputType(mc, result.isBinaryFormat()), responseVariable, overwriteBody);
    }

    @Override
    protected String operationName() {
        return "verify";
    }
}
