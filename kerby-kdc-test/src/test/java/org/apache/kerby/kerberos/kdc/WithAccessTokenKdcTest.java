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

import org.apache.kerby.kerberos.kerb.spec.base.AuthToken;
import org.apache.kerby.kerberos.kerb.spec.ticket.ServiceTicket;
import org.junit.Test;

import java.io.File;

import static org.assertj.core.api.Assertions.assertThat;

public class WithAccessTokenKdcTest extends WithTokenKdcTestBase {
    private File cCacheFile;
    private AuthToken authToken;

    private String clientPrincipal;
    private String serverPrincipal;
    private String servicePrincipal;

    @Override
    protected void setUpKdcServer() throws Exception {
        super.setUpKdcServer();
        servicePrincipal = "hdfs@" + kdcRealm;
    }

    @Override
    protected void createPrincipals() {
        super.createPrincipals();
        clientPrincipal = getClientPrincipal();
        kdcServer.createPrincipal(clientPrincipal, TEST_PASSWORD);
        kdcServer.createPrincipal(servicePrincipal, TEST_PASSWORD);
    }

    @Test
    public void testRequestServiceTicketWithAccessToken() throws Exception {
        authToken = prepareToken(true);
        cCacheFile = createCredentialCache(clientPrincipal, TEST_PASSWORD);
        serverPrincipal = getServerPrincipal();
        ServiceTicket serviceTicket = krbClnt.requestServiceTicketWithAccessToken(
            authToken, serverPrincipal, cCacheFile.getPath());
        assertThat(serviceTicket).isNotNull();
        assertThat(serviceTicket.getRealm()).isEqualTo(kdcRealm);
        assertThat(serviceTicket.getTicket()).isNotNull();
        assertThat(serviceTicket.getSessionKey()).isNotNull();
        assertThat(serviceTicket.getEncKdcRepPart()).isNotNull();

        deleteCcacheFile();
    }
}
