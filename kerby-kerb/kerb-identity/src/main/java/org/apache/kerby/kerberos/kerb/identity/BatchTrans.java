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
package org.apache.kerby.kerberos.kerb.identity;

import org.apache.kerby.kerberos.kerb.KrbException;

/**
 * Batch operations support to create/update/delete principal accounts
 * in a transaction.
 */
public interface BatchTrans {

    /**
     * Commit this transaction, releasing any associated resources.
     * @throws KrbException
     */
    void commit() throws KrbException;

    /**
     * Give up this transaction, releasing any associated resources.
     * @throws KrbException
     */
    void rollback() throws KrbException;

    /**
     * Add an identity, and return the newly created result.
     * @param identity The identity
     * @return BatchTrans
     * @throws KrbException e
     */
    BatchTrans addIdentity(KrbIdentity identity) throws KrbException;

    /**
     * Update an identity, and return the updated result.
     * @param identity The identity
     * @return BatchTrans
     * @throws KrbException e
     */
    BatchTrans updateIdentity(KrbIdentity identity) throws KrbException;

    /**
     * Delete the identity specified by principal name
     * @param principalName The principal name
     * @return BatchTrans
     * @throws KrbException e
     */
    BatchTrans deleteIdentity(String principalName) throws KrbException;
}
