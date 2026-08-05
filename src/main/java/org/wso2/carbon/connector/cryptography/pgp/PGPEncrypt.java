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

import org.bouncycastle.openpgp.PGPPublicKey;
import org.wso2.carbon.connector.cryptography.exception.CryptoException;
import org.wso2.carbon.connector.cryptography.pgp.connection.PgpKeyStore;
import org.wso2.carbon.connector.cryptography.pgp.constant.PGPCryptoConstants;
import org.wso2.carbon.connector.cryptography.pgp.constant.PGPParameterKey;
import org.wso2.carbon.connector.cryptography.pgp.util.PGPCryptoUtils;
import org.wso2.carbon.connector.cryptography.pgp.util.PGPKeyUtils;
import org.apache.synapse.MessageContext;

/**
 * Encrypts the input payload for a recipient using their public key (confidentiality).
 */
public class PGPEncrypt extends AbstractPGPOperation {

    @Override
    protected void executePgp(MessageContext mc, String responseVariable, Boolean overwriteBody)
            throws CryptoException {
        // Outbound: plaintext carriage is an explicit choice (TEXT default; BINARY for a base64-carried file).
        String inType = inputType(mc, PGPCryptoConstants.MSG_TYPE_BINARY);
        byte[] input = readInput(mc, inType);
        boolean textMode = PGPCryptoConstants.MSG_TYPE_TEXT.equals(inType);

        PgpKeyStore recipientStore = requirePublicStore(mc, PGPParameterKey.ENCRYPTION_CONFIG_KEY);
        int symmetric = PGPCryptoConstants.resolveSymmetricKeyAlgorithm(
                param(mc, PGPParameterKey.SYMMETRIC_KEY_ALGORITHM, PGPCryptoConstants.DEFAULT_SYMMETRIC_ALGORITHM));
        int compression = PGPCryptoConstants.resolveCompressionAlgorithm(
                param(mc, PGPParameterKey.COMPRESSION_ALGORITHM, PGPCryptoConstants.DEFAULT_COMPRESSION_ALGORITHM));
        boolean armor = boolParam(mc, PGPParameterKey.ARMOR, PGPCryptoConstants.DEFAULT_ARMOR);
        boolean integrity = boolParam(mc, PGPParameterKey.INTEGRITY_CHECK, PGPCryptoConstants.DEFAULT_INTEGRITY_CHECK);
        String fileName = param(mc, PGPParameterKey.FILE_NAME);

        PGPPublicKey publicKey = PGPKeyUtils.selectEncryptionKey(recipientStore.getPublicKeys(),
                recipientStore.getSelector());
        byte[] output = PGPCryptoUtils.encrypt(input, publicKey, symmetric, compression, armor, integrity,
                textMode, fileName);

        emitResult(mc, output, outboundOutputType(mc, armor), responseVariable, overwriteBody);
    }

    @Override
    protected String operationName() {
        return "encrypt";
    }
}
