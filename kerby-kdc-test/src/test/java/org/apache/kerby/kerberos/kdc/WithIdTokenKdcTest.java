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
package org.apache.kerby.kerberos.kdc;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.spec.base.AuthToken;
import org.apache.kerby.kerberos.kerb.spec.ticket.ServiceTicket;
import org.apache.kerby.kerberos.kerb.spec.ticket.TgtTicket;
import org.junit.Test;

import java.io.File;

import static org.assertj.core.api.Assertions.assertThat;

public class WithIdTokenKdcTest extends WithTokenKdcTestBase {

    private File cCacheFile;
    private AuthToken authToken;

    private String clientPrincipal;
    private String serverPrincipal;

    @Override
    protected void createPrincipals() {
        super.createPrincipals();
        clientPrincipal = getClientPrincipal();
        kdcServer.createPrincipal(clientPrincipal, TEST_PASSWORD);
    }

    @Test
    public void testKdc() throws Exception {

        authToken = prepareToken(false);
        cCacheFile = createCredentialCache(clientPrincipal, TEST_PASSWORD);

        TgtTicket tgt = null;
        try {
            tgt = krbClnt.requestTgtWithToken(authToken, cCacheFile.getPath());
        } catch (KrbException e) {
            assertThat(e.getMessage().contains("timeout")).isTrue();
            return;
        }
        assertThat(tgt).isNotNull();
        assertThat(tgt.getClientPrincipal()).isEqualTo(SUBJECT + "@" + kdcRealm);
        assertThat(tgt.getRealm()).isEqualTo(kdcRealm);
        assertThat(tgt.getTicket()).isNotNull();
        assertThat(tgt.getEncKdcRepPart()).isNotNull();
        assertThat(tgt.getSessionKey()).isNotNull();

        serverPrincipal = getServerPrincipal();
        ServiceTicket tkt = krbClnt.requestServiceTicketWithTgt(tgt, serverPrincipal);
        assertThat(tkt).isNotNull();
        assertThat(tkt.getRealm()).isEqualTo(kdcRealm);
        assertThat(tkt.getTicket()).isNotNull();
        assertThat(tkt.getSessionKey()).isNotNull();
        assertThat(tkt.getEncKdcRepPart()).isNotNull();
    }
}