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

import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.wso2.carbon.connector.cryptography.exception.CryptoException;
import org.wso2.carbon.connector.cryptography.pgp.connection.PgpKeyStore;
import org.wso2.carbon.connector.cryptography.pgp.constant.PGPCryptoConstants;
import org.wso2.carbon.connector.cryptography.pgp.constant.PGPParameterKey;
import org.wso2.carbon.connector.cryptography.pgp.model.KeySelector;
import org.wso2.carbon.connector.cryptography.pgp.util.PGPCryptoUtils;
import org.wso2.carbon.connector.cryptography.pgp.util.PGPKeyUtils;
import org.apache.synapse.MessageContext;

/**
 * Signs the input payload with your private key (authenticity, integrity, non-repudiation).
 */
public class PGPSign extends AbstractPGPOperation {

    @Override
    protected void executePgp(MessageContext mc, String responseVariable, Boolean overwriteBody)
            throws CryptoException {
        // Outbound: plaintext carriage is an explicit choice (TEXT default; BINARY for a base64-carried file).
        String inType = inputType(mc, PGPCryptoConstants.MSG_TYPE_BINARY);
        byte[] input = readInput(mc, inType);
        boolean textMode = PGPCryptoConstants.MSG_TYPE_TEXT.equals(inType);

        PgpKeyStore signingStore = requirePrivateStore(mc, PGPParameterKey.SIGNING_CONFIG_KEY);
        String passphrase = signingStore.getPassphrase();
        KeySelector signer = signingStore.getSelector();
        int hash = PGPCryptoConstants.resolveHashAlgorithm(
                param(mc, PGPParameterKey.SIGNATURE_HASH_ALGORITHM, PGPCryptoConstants.DEFAULT_HASH_ALGORITHM));
        int compression = PGPCryptoConstants.resolveCompressionAlgorithm(
                param(mc, PGPParameterKey.COMPRESSION_ALGORITHM, PGPCryptoConstants.DEFAULT_COMPRESSION_ALGORITHM));
        boolean armor = boolParam(mc, PGPParameterKey.ARMOR, PGPCryptoConstants.DEFAULT_ARMOR);
        String fileName = param(mc, PGPParameterKey.FILE_NAME);

        PGPSecretKey signingKey = PGPKeyUtils.findSigningSecretKey(signingStore.getSecretKeys(), signer);
        PGPPrivateKey privateKey = PGPKeyUtils.extractPrivateKey(signingKey, passphrase);

        byte[] output = PGPCryptoUtils.sign(input, signingKey, privateKey, hash, compression, armor,
                textMode, fileName);

        emitResult(mc, output, outboundOutputType(mc, armor), responseVariable, overwriteBody);
    }

    @Override
    protected String operationName() {
        return "sign";
    }
}
