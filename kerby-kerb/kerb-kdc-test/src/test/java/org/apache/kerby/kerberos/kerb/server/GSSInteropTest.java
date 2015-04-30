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
package org.apache.kerby.kerberos.kerb.server;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Principal;
import java.security.PrivilegedExceptionAction;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.login.LoginContext;

import org.apache.commons.io.IOUtils;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * This is an interop test using the Java GSS APIs against the Kerby KDC
 */
public class GSSInteropTest extends KdcTest {
    
    @Override
    protected void setUpKdcServer() throws Exception {
        kdcServer = new TestKdcServer();
        prepareKdcServer();
        
        kdcServer.init();
        
        // Must disable pre-auth
        kdcServer.getSetting().getKdcConfig().setBoolean(KdcConfigKey.PREAUTH_REQUIRED, false);
        
        kdcRealm = kdcServer.getKdcRealm();
        clientPrincipal = "drankye@" + kdcRealm;
        serverPrincipal = "test-service/localhost@" + kdcRealm;
    }
    
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        
        String basedir = System.getProperty("basedir");
        if (basedir == null) {
            basedir = new File(".").getCanonicalPath();
        }
        
        // System.setProperty("sun.security.krb5.debug", "true");
        System.setProperty("java.security.auth.login.config", 
                           basedir + "/src/test/resources/kerberos.jaas");
        
        // Read in krb5.conf and substitute in the correct port
        File f = new File(basedir + "/src/test/resources/krb5.conf");

        FileInputStream inputStream = new FileInputStream(f);
        String content = IOUtils.toString(inputStream, "UTF-8");
        inputStream.close();
        content = content.replaceAll("port", "" + tcpPort);

        File f2 = new File(basedir + "/target/test-classes/krb5.conf");
        FileOutputStream outputStream = new FileOutputStream(f2);
        IOUtils.write(content, outputStream, "UTF-8");
        outputStream.close();

        System.setProperty("java.security.krb5.conf", f2.getPath());
    }

    @Override
    protected boolean allowUdp() {
        return false;
    }

    @Test
    public void testKdc() throws Exception {
        kdcServer.start();
        
        LoginContext loginContext = new LoginContext("drankye", new KerberosCallbackHandler());
        loginContext.login();
        
        Subject clientSubject = loginContext.getSubject();
        Set<Principal> clientPrincipals = clientSubject.getPrincipals();
        Assert.assertFalse(clientPrincipals.isEmpty());

        // Get the TGT
        Set<KerberosTicket> privateCredentials = 
            clientSubject.getPrivateCredentials(KerberosTicket.class);
        Assert.assertFalse(privateCredentials.isEmpty());
        KerberosTicket tgt = privateCredentials.iterator().next();
        Assert.assertNotNull(tgt);

        // Get the service ticket
        KerberosClientExceptionAction action =
            new KerberosClientExceptionAction(clientPrincipals.iterator().next(), 
                                              "test-service/localhost@TEST.COM");
        
        byte[] kerberosToken = (byte[]) Subject.doAs(clientSubject, action);
        Assert.assertNotNull(kerberosToken);
    }
    
    private static class KerberosCallbackHandler implements CallbackHandler {

        public void handle(Callback[] callbacks) throws IOException,
                UnsupportedCallbackException {
            for (int i = 0; i < callbacks.length; i++) {
                if (callbacks[i] instanceof PasswordCallback) {
                    PasswordCallback pc = (PasswordCallback) callbacks[i];
                    if (pc.getPrompt().contains("drankye")) {
                        pc.setPassword(TEST_PASSWORD.toCharArray());
                        break;
                    }
                }
            }
        }
    }
    
    /**
     * This class represents a PrivilegedExceptionAction implementation to obtain a service ticket from a Kerberos
     * Key Distribution Center.
     */
    private static class KerberosClientExceptionAction implements PrivilegedExceptionAction<byte[]> {

        private static final String JGSS_KERBEROS_TICKET_OID = "1.2.840.113554.1.2.2";
        
        private Principal clientPrincipal;
        private String serviceName;

        public KerberosClientExceptionAction(Principal clientPrincipal, String serviceName) { 
            this.clientPrincipal = clientPrincipal;
            this.serviceName = serviceName;
        }
        
        public byte[] run() throws GSSException {
            GSSManager gssManager = GSSManager.getInstance();

            GSSName gssService = gssManager.createName(serviceName, GSSName.NT_USER_NAME);
            Oid oid = new Oid(JGSS_KERBEROS_TICKET_OID);
            GSSName gssClient = gssManager.createName(clientPrincipal.getName(), GSSName.NT_USER_NAME);
            GSSCredential credentials = 
                gssManager.createCredential(
                    gssClient, GSSCredential.DEFAULT_LIFETIME, oid, GSSCredential.INITIATE_ONLY
                );

            GSSContext secContext =
                gssManager.createContext(
                    gssService, oid, credentials, GSSContext.DEFAULT_LIFETIME
                );

            secContext.requestMutualAuth(false);
            secContext.requestCredDeleg(false);

            try {
                byte[] token = new byte[0];
                byte[] returnedToken = secContext.initSecContext(token, 0, token.length);

                return returnedToken;
            } finally {
                secContext.dispose();
            }
        }
    }
}