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

import org.apache.kerby.kerberos.kerb.KrbRuntime;
import org.apache.kerby.kerberos.kerb.ccache.Credential;
import org.apache.kerby.kerberos.kerb.ccache.CredentialCache;
import org.apache.kerby.kerberos.kerb.server.KdcTestBase;
import org.apache.kerby.kerberos.kerb.spec.base.AuthToken;
import org.apache.kerby.kerberos.kerb.spec.ticket.TgtTicket;
import org.apache.kerby.kerberos.provider.token.JwtTokenProvider;
import org.junit.Before;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class WithTokenKdcTestBase extends KdcTestBase {
    static final String SUBJECT = "drankye";
    static final String AUDIENCE = "krbtgt@EXAMPLE.COM";
    static final String ISSUER = "oauth2.com";
    static final String GROUP = "sales-group";
    static final String ROLE = "ADMIN";
    private File cCacheFile;

    private AuthToken authToken;

    private String clientPrincipal;
    private String serverPrincipal;
    private String servicePrincipal;

    @Before
    public void setUp() throws Exception {
        KrbRuntime.setTokenProvider(new JwtTokenProvider());

        super.setUp();

        kdcServer.start();
        krbClnt.init();
    }

    protected AuthToken prepareToken(boolean isAcToken) {
        authToken = KrbRuntime.getTokenProvider().createTokenFactory().createToken();

        if (isAcToken) {
            authToken.setIsAcToken(true);
        }

        authToken.setIssuer(ISSUER);
        authToken.setSubject(SUBJECT);

        authToken.addAttribute("group", GROUP);
        authToken.addAttribute("role", ROLE);

        List<String> aud = new ArrayList<String>();
        aud.add(AUDIENCE);
        authToken.setAudiences(aud);

        // Set expiration in 60 minutes
        final Date NOW =  new Date(new Date().getTime() / 1000 * 1000);
        Date exp = new Date(NOW.getTime() + 1000 * 60 * 60);
        authToken.setExpirationTime(exp);

        Date nbf = NOW;
        authToken.setNotBeforeTime(nbf);

        Date iat = NOW;
        authToken.setIssueTime(iat);
        return authToken;
    }

    @Override
    protected void prepareKdcServer() throws Exception {
        super.prepareKdcServer();
    }

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

    protected File createCredentialCache(String principal,
                                       String password) throws Exception {
        TgtTicket tgt = krbClnt.requestTgtWithPassword(principal, password);
        writeTgtToCache(tgt, principal);
        return cCacheFile;
    }

    /**
     * Write tgt into credentials cache.
     */
    private void writeTgtToCache(
            TgtTicket tgt, String principal) throws IOException {
        Credential credential = new Credential(tgt);
        CredentialCache cCache = new CredentialCache();
        cCache.addCredential(credential);
        cCache.setPrimaryPrincipal(tgt.getClientPrincipal());

        String fileName = "krb5_" + principal + ".cc";
        cCacheFile = new File(getTestDir().getPath(), fileName);
        cCache.store(cCacheFile);
    }

    protected void deleteCcacheFile() {
        cCacheFile.delete();
    }

    @Override
    protected void deletePrincipals() {
        super.deletePrincipals();
        kdcServer.deletePrincipals(clientPrincipal, servicePrincipal);
    }
}
