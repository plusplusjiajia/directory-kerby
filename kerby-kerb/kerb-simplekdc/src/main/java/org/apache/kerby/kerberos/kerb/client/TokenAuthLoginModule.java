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

import org.apache.kerby.kerberos.kerb.spec.base.KrbToken;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.kerberos.KeyTab;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;


public class TokenAuthLoginModule implements LoginModule {
    // initial state
    private Subject subject;
    private CallbackHandler callbackHandler;
    private Map sharedState;
    private Map<String, ?> options;

    // configurable option
    private boolean useToken = false;
    private boolean useDefaultTokenCache = false;
    private String tokenCacheName = null;

    // the authentication status
    private boolean succeeded = false;
    private boolean commitSucceeded = false;

    private String token = null;
    private File ccacheFile;
    private static final String TOKEN = ".tokenauth.token";


    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler,
                           Map<String, ?> sharedState, Map<String, ?> options) {

        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.sharedState = sharedState;
        this.options = options;

        // initialize any configured options
        useToken = "true".equalsIgnoreCase((String) options.get("useToken"));
        token = (String) options.get("token");
        tokenCacheName = (String) options.get("tokenCache");
        useDefaultTokenCache = "true".equalsIgnoreCase((String) options.get
                ("useDefaultTokenCache"));
    }

    @Override
    public boolean login() throws LoginException {
        validateConfiguration();

        Map<String, ?> krbOptions = this.options;
        Map krbSharedState = this.sharedState;

        if (useToken) {
            boolean result = tokenLogin();
            if (!result) {
                return false;
            }

            Map<String, Object> newOptions = new HashMap<String, Object>();
            newOptions.putAll(this.options);
            newOptions.put("useTicketCache", "true");
            newOptions.put("ticketCache", ccacheFile.getAbsolutePath());
            krbOptions = newOptions;

            Map newSharedState = new HashMap();
            newSharedState.putAll(this.sharedState);
            krbSharedState = newSharedState;
        }

//        krb5LoginModule = new Krb5LoginModule();
//        krb5LoginModule.initialize(subject, null, krbSharedState, krbOptions);
//        succeeded = krb5LoginModule.login();

        return succeeded;
    }

    @Override
    public boolean commit() throws LoginException {
//        boolean result = krb5LoginModule.commit();
//        if (result && useToken) {
        if(useToken)
            try {
                KrbToken krbToken = TokenTool.fromJwtToken(token);
                subject.getPublicCredentials().add(krbToken); // better put in private set?
            } catch (ParseException e) {
                throwWith("Failed to convert from JWT token", e);
            }
        }
        return result;
    }

    @Override
    public boolean abort() throws LoginException {
        if (succeeded == false) {
            return false;
        } else if (succeeded == true && commitSucceeded == false) {
            // login succeeded but overall authentication failed
            succeeded = false;
            cleanKerberosCred();
        } else {
            // overall authentication succeeded and commit succeeded,
            // but someone else's commit failed
            logout();
        }
        return true;
    }

    @Override
    public boolean logout() throws LoginException {
//        if (debug) {
//            System.out.println("\t\t[Krb5LoginModule]: " +
//                    "Entering logout");
//        }

        if (subject.isReadOnly()) {
            cleanKerberosCred();
            throw new LoginException("Subject is Readonly");
        }

        subject.getPrincipals().remove(kerbClientPrinc);
        // Let us remove all Kerberos credentials stored in the Subject
        Iterator<Object> it = subject.getPrivateCredentials().iterator();
        while (it.hasNext()) {
            Object o = it.next();
            if (o instanceof KerberosTicket ||
                    o instanceof KerberosKey ||
                    o instanceof KeyTab) {
                it.remove();
            }
        }
        // clean the kerberos ticket and keys
        cleanKerberosCred();

        succeeded = false;
        commitSucceeded = false;
//        if (debug) {
//            System.out.println("\t\t[Krb5LoginModule]: " +
//                    "logged out Subject");
//        }
        return true;
    }

    private boolean tokenLogin() throws LoginException {
        doTokenLogin();
        return true;
    }

    private void validateConfiguration() throws LoginException {
        if (!useToken) return;

        String error = "";
        if (useDefaultTokenCache) {
            if (token != null || tokenCacheName != null) {
                error = "useDefaultTokenCache is specified, but token or tokenCacheName is also specified";
            }
        } else {
            if (token == null && tokenCacheName == null) {
                error = "useToken is specified but no token or token cache is provided";
            } else if (token != null && tokenCacheName != null) {
                error = "either token or token cache should be provided but not both";
            }
        }

        if (!error.isEmpty()) {
            throw new LoginException(error);
        }
    }

    private void doTokenLogin() throws LoginException {
        if (token == null) {
            token = TokenCache.readToken(tokenCacheName);
            if (token == null) {
                throw new LoginException("No valid token was found in token cache: " + tokenCacheName);
            }
        }

        try {
            ccacheFile = makeCcacheFile();
        } catch (IOException e) {
            throwWith("Failed to create tmp ccache file", e);
        }

        String[] tokenInitCmd = null;
        if (useDefaultTokenCache && token == null) {
            tokenInitCmd = new String[]{
                    "ktinit.sh", "-c", ccacheFile.getAbsolutePath()
            };
        } else {
            tokenInitCmd = new String[]{
                    "ktinit.sh", "-t", token, "-c", ccacheFile.getAbsolutePath()
            };
        }

        Process proc = null;
        BufferedReader reader;
        try {
            proc = Runtime.getRuntime().exec(tokenInitCmd);
        } catch (IOException e) {
            throwWith("Failed to do token init with token: " + token, e);
        }

        int exitCode = 1;
        reader = new BufferedReader(new InputStreamReader(
                proc.getInputStream()));
        try {
            exitCode = proc.waitFor();
        } catch (InterruptedException e) {
            throwWith("Failed to do token init with token: " + token, e);
        }

        if (exitCode != 0) {
            String errors = "";
            StringBuffer lines = new StringBuffer();
            String line;
            try {
                while (reader.ready()) {
                    line = reader.readLine();
                    lines.append(line).append("\n");
                }
                errors = lines.toString();
            } catch (IOException e) {
                errors = e.getMessage();
            }
            throw new RuntimeException(errors);
        }
    }

    private File makeCcacheFile() throws IOException {
        File ccacheFile = File.createTempFile("/tmp/krb5cc_token", ".tmp");
        ccacheFile.setExecutable(false);
        ccacheFile.setReadable(true);
        ccacheFile.setWritable(true);

        return ccacheFile;
    }

    private void cleanup() {
        if (useToken) {
            if (ccacheFile != null && ccacheFile.exists()) {
                ccacheFile.delete();
            }
        }
    }

    private void throwWith(String error, Exception cause) throws LoginException {
        LoginException le = new LoginException(error);
        le.initCause(cause);
        throw le;
    }
}
