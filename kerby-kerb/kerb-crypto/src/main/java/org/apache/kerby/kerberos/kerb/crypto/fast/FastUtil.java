/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.kerby.kerberos.kerb.crypto.fast;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.ccache.Credential;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.ap.ApOptions;
import org.apache.kerby.kerberos.kerb.spec.ap.ApReq;
import org.apache.kerby.kerberos.kerb.spec.ap.Authenticator;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.base.KeyUsage;
import org.apache.kerby.kerberos.kerb.spec.fast.ArmorType;
import org.apache.kerby.kerberos.kerb.spec.fast.KrbFastArmor;
import org.apache.kerby.kerberos.kerb.spec.ticket.Ticket;

/**
 * Implementing FAST (RFC6113) armor key related algorithms.
 * Take two keys and two pepper strings as input and return a combined key.
 */
public class FastUtil {


    /**
     * Call the PRF function multiple times with the pepper prefixed with
     * a count byte  to get enough bits of output.
     */

    public static byte[] prfPlus(EncryptionKey key, String pepper,
                                 int keyBytesLen) throws KrbException {
        byte[] prfInbuf = new byte[pepper.length() + 1];
        byte[] tmpbuf = new byte[keyBytesLen];
        int prfSize = EncryptionHandler.getEncHandler(key.getKeyType()).prfSize();
        int iterations = keyBytesLen / prfSize;
        prfInbuf[0] = 1;
        System.arraycopy(pepper.getBytes(), 0, prfInbuf, 1, pepper.length());
        if (keyBytesLen % prfSize !=0) {
            iterations++;
        }
        byte[] buffer = new byte[prfSize * iterations];
        for (int i = 0; i < iterations; i++) {
            System.arraycopy(EncryptionHandler.getEncHandler(key.getKeyType()).prf(key.getKeyData(), prfInbuf), 0, buffer, i * prfSize, prfSize);
            prfInbuf[0]++;
        }
        System.arraycopy(buffer, 0, tmpbuf, 0, keyBytesLen);
        return tmpbuf;
    }

    public static EncryptionKey cf2(EncryptionKey key1, String pepper1,
                                    EncryptionKey key2, String pepper2) throws KrbException {
        int keyBites = EncryptionHandler.getEncHandler(key1.getKeyType()).encProvider().keyInputSize();
        byte[] buf1 = prfPlus(key1, pepper1, keyBites);
        byte[] buf2 = prfPlus(key2, pepper2, keyBites);
        for (int i = 0; i < keyBites; i++) {
            buf1[i] ^= buf2[i];
        }
        EncryptionKey outKey = EncryptionHandler.random2Key(key1.getKeyType(), buf1);
        return outKey;
    }

    /**
     * Make an encryption key for replying.
     * @param strengthenKey
     * @param existingKey
     * @return encryption key
     */
    public static EncryptionKey makeReplyKey(EncryptionKey strengthenKey,
                                             EncryptionKey existingKey) throws KrbException {
        return cf2(strengthenKey, "strengthenkey", existingKey, "replykey");
    }

    /**
     * Make an encryption key for armoring.
     * @param subkey
     * @param ticketKey
     * @return encryption key
     */
    public static EncryptionKey makeArmorKey(EncryptionKey subkey,
                                             EncryptionKey ticketKey) throws KrbException {
        return cf2(subkey, "subkeyarmor", ticketKey, "ticketarmor");
    }

    public static KrbFastArmor fastArmorApRequest(EncryptionKey subKey, Credential credential)
        throws KrbException {
        KrbFastArmor fastArmor = new KrbFastArmor();
        fastArmor.setArmorType(ArmorType.ARMOR_AP_REQUEST);
        ApReq apReq = makeApReq(subKey, credential);
        fastArmor.setArmorValue(apReq.encode());
        return fastArmor;
    }

    private static ApReq makeApReq(EncryptionKey subKey, Credential credential) throws KrbException {
        ApReq apReq = new ApReq();
        ApOptions apOptions = new ApOptions();
        apReq.setApOptions(apOptions);
        Ticket ticket = credential.getTicket();
        apReq.setTicket(ticket);
        Authenticator authenticator = makeAuthenticator(subKey, credential);
        apReq.setAuthenticator(authenticator);
        EncryptedData authnData = EncryptionUtil.seal(authenticator,
            credential.getKey(), KeyUsage.AP_REQ_AUTH);
        apReq.setEncryptedAuthenticator(authnData);
        return apReq;
    }

    private static Authenticator makeAuthenticator(EncryptionKey subKey, Credential credential) throws KrbException {
        Authenticator authenticator = new Authenticator();
        authenticator.setCname(credential.getClientName());
        authenticator.setCrealm(credential.getClientRealm());
        authenticator.setCtime(KerberosTime.now());
        authenticator.setCusec(0);
        authenticator.setSubKey(subKey);
        return authenticator;
    }
}
