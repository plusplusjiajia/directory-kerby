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
package org.apache.kerby.kerberos.kerb.client;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.KrbRuntime;
import org.apache.kerby.kerberos.kerb.provider.TokenDecoder;
import org.apache.kerby.kerberos.kerb.spec.base.AuthToken;
import org.apache.kerby.kerberos.kerb.spec.base.KrbToken;
import org.apache.kerby.kerberos.kerb.spec.base.TokenFormat;
import org.apache.kerby.kerberos.kerb.spec.ticket.TgtTicket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.File;
import java.io.IOException;
import java.util.Iterator;
import java.util.Map;


public class TokenAuthLoginModule implements LoginModule {
    private static final Logger LOG = LoggerFactory.getLogger(TokenAuthLoginModule.class);

    // initial state
    private Subject subject;

    // configurable option
    private boolean useToken = false;
    private boolean useDefaultTokenCache = false;
    private String tokenCacheName = null;

    // the authentication status
    private boolean succeeded = false;
    private boolean commitSucceeded = false;

     private String princName = null;
    private String tokenStr = null;
    private AuthToken authToken = null;
    KrbToken krbToken = null;
    private File ccacheFile;
    private File armorCache;
    private int tcpPort;
    private int udpPort;
    private String kdcRealm;


    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler,
                           Map<String, ?> sharedState, Map<String, ?> options) {

        this.subject = subject;

        princName = (String)options.get("principal");
        // initialize any configured options
        useToken = "true".equalsIgnoreCase((String) options.get("useToken"));
        tokenStr = (String) options.get("token");
        tokenCacheName = (String) options.get("tokenCache");
        useDefaultTokenCache = "true".equalsIgnoreCase((String) options.get
                ("useDefaultTokenCache"));
        armorCache = new File((String) options.get("armorCache"));
        tcpPort = Integer.parseInt((String) options.get("tcpPort"));
        udpPort = Integer.parseInt((String) options.get("udpPort"));
        kdcRealm = (String) options.get("realm");
    }

    @Override
    public boolean login() throws LoginException {
        validateConfiguration();

        if (useToken) {
            boolean result = tokenLogin();
            succeeded = result;
        } else {
            return false;
        }
        return succeeded;
    }

    @Override
    public boolean commit() throws LoginException {

        if (succeeded == false) {
            return false;
        } else {
            if(useToken) {
                subject.getPublicCredentials().add(krbToken); // better put in private set?
            }
        }
        commitSucceeded = true;
        LOG.info("Commit Succeeded \n");
        return true;
    }

    @Override
    public boolean abort() throws LoginException {
        if (succeeded == false) {
            return false;
        } else if (succeeded == true && commitSucceeded == false) {
            // login succeeded but overall authentication failed
            succeeded = false;
        } else {
            // overall authentication succeeded and commit succeeded,
            // but someone else's commit failed
            logout();
        }
        return true;
    }

    @Override
    public boolean logout() throws LoginException {
        LOG.info("\t\t[TokenAuthLoginModule]: Entering logout");

        if (subject.isReadOnly()) {
            throw new LoginException("Subject is Readonly");
        }

        subject.getPrincipals().remove(princName);
        // Let us remove all Kerberos credentials stored in the Subject
        Iterator<Object> it = subject.getPrivateCredentials().iterator();
        while (it.hasNext()) {
            Object o = it.next();
            if (o instanceof KrbToken) {
                it.remove();
            }
        }

        cleanup();

        succeeded = false;
        commitSucceeded = false;

        LOG.info("\t\t[TokenAuthLoginModule]: logged out Subject");
        return true;
    }

    private void validateConfiguration() throws LoginException {
        if (!useToken) return;

        String error = "";
        if (useDefaultTokenCache) {
            if (tokenStr != null || tokenCacheName != null) {
                error = "useDefaultTokenCache is specified, but token or tokenCacheName is also specified";
            }
        } else {
            if (tokenStr == null && tokenCacheName == null) {
                error = "useToken is specified but no token or token cache is provided";
            } else if (tokenStr != null && tokenCacheName != null) {
                error = "either token or token cache should be provided but not both";
            }
        }

        if (!error.isEmpty()) {
            throw new LoginException(error);
        }
    }

    private boolean tokenLogin() throws LoginException {
        if (tokenStr == null) {
            tokenStr = TokenCache.readToken(tokenCacheName);
            if (tokenStr == null) {
                throw new LoginException("No valid token was found in token cache: " + tokenCacheName);
            }
        }

        TokenDecoder tokenDecoder = KrbRuntime.getTokenProvider().createTokenDecoder();
        try {
            authToken = tokenDecoder.decodeFromString(tokenStr);
        } catch (IOException e) {
            e.printStackTrace();
        }

        krbToken = new KrbToken(authToken, TokenFormat.JWT);

        KrbClient krbClient = null;
        try {
            krbClient = new KrbClient();
            krbClient.setKdcTcpPort(tcpPort);
            krbClient.setKdcUdpPort(udpPort);
            krbClient.setKdcRealm(kdcRealm);
            krbClient.init();
        } catch (KrbException e) {
            e.printStackTrace();
        }

        TgtTicket tgtTicket = null;
        try {
            tgtTicket = krbClient.requestTgtWithToken(krbToken, armorCache.getAbsolutePath());
        } catch (KrbException e) {
            throwWith("Failed to do login with token: " + tokenStr, e);
            return false;
        }

        try {
            ccacheFile = makeCcacheFile();
        } catch (IOException e) {
            throwWith("Failed to create tmp ccache file", e);
        }
        try {
            krbClient.storeTicket(tgtTicket, ccacheFile);
        } catch (KrbException e) {
            e.printStackTrace();
        }
        return true;
    }

    private File makeCcacheFile() throws IOException {
        File ccacheFile = File.createTempFile("/tmp/krb5cc_token", ".tmp");
        ccacheFile.setExecutable(false);
        ccacheFile.setReadable(true);
        ccacheFile.setWritable(true);

        return ccacheFile;
    }

    private void cleanup() {
        if (useToken && ccacheFile != null && ccacheFile.exists()) {
            ccacheFile.delete();
        }
    }

    private void throwWith(String error, Exception cause) throws LoginException {
        LoginException le = new LoginException(error);
        le.initCause(cause);
        throw le;
    }
}
