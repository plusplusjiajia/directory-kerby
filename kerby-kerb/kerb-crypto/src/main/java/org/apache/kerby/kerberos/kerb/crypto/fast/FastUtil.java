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

import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;

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
                                 int keyBytesLen) {
        // TODO
        return null;
    }

    public static EncryptionKey cf2(EncryptionKey key1, String pepper1,
                                    EncryptionKey key2, String pepper2) {
        // TODO
        return null;
    }

    /**
     * Make an encryption key for replying.
     * @param strengthenKey
     * @param existingKey
     * @return encryption key
     */
    public static EncryptionKey makeReplyKey(EncryptionKey strengthenKey,
                                      EncryptionKey existingKey) {
        return cf2(strengthenKey, "strengthenkey", existingKey, "replykey");
    }

    /**
     * Make an encryption key for armoring.
     * @param subkey
     * @param ticketKey
     * @return encryption key
     */
    public static EncryptionKey makeArmorKey(EncryptionKey subkey,
                                             EncryptionKey ticketKey) {
        return cf2(subkey, "subkeyarmor", ticketKey, "ticketarmor");
    }
}
