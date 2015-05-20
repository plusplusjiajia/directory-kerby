package org.apache.kerby.kerberos.kerb.common;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.crypto.CheckSumHandler;
import org.apache.kerby.kerberos.kerb.crypto.EncTypeHandler;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.spec.base.CheckSum;
import org.apache.kerby.kerberos.kerb.spec.base.CheckSumType;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.base.KeyUsage;

public class CheckSumUtil {

    public static CheckSum makeCheckSum(CheckSumType checkSumType, byte[] input, EncryptionKey key,
                                        KeyUsage usage) throws KrbException {
        if (checkSumType == CheckSumType.NONE) {
            EncTypeHandler handler = EncryptionHandler.getEncHandler(key.getKeyType());
            checkSumType = handler.checksumType();
        }
        return CheckSumHandler.checksumWithKey(checkSumType, input, key.getKeyData(), usage);
    }
}