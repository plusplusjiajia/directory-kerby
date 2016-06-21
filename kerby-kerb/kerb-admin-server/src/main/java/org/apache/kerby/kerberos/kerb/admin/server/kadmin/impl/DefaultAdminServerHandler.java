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
package org.apache.kerby.kerberos.kerb.admin.server.kadmin.impl;

import org.apache.kerby.kerberos.kerb.admin.server.kadmin.AdminServerContext;
import org.apache.kerby.kerberos.kerb.admin.server.kadmin.AdminServerHandler;
import org.apache.kerby.kerberos.kerb.admin.server.kadmin.sasl.KerbySaslServer;
import org.apache.kerby.kerberos.kerb.transport.KrbTransport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslServer;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

public class DefaultAdminServerHandler extends AdminServerHandler implements Runnable {
    private static Logger logger = LoggerFactory.getLogger(DefaultAdminServerHandler.class);
    private final KrbTransport transport;
    private boolean sasl = false;

    public DefaultAdminServerHandler(AdminServerContext adminServerContext, KrbTransport transport) {
        super(adminServerContext);
        this.transport  = transport;
    }

    @Override
    public void run() {
        while (true) {
            try {
                ByteBuffer message = transport.receiveMessage();
                if (message == null) {
                    logger.debug("No valid request recved. Disconnect actively");
                    transport.release();
                    break;
                }
                handleMessage(message);
            } catch (IOException e) {
                transport.release();
                logger.debug("Transport or decoding error occurred, "
                        + "disconnecting abnormally", e);
                break;
            }
        }
    }

    protected void handleMessage(ByteBuffer message) {
        InetAddress clientAddress = transport.getRemoteAddress();

        if (!sasl) {
            SaslServer saslServer = null;
            try {
                saslServer = sasl();
                byte[] challenge = saslServer.evaluateResponse(message.array());
                transport.sendMessage(ByteBuffer.wrap(challenge));
            } catch (Exception e) {
                e.printStackTrace();
            }
            sasl = true;
        }


        try {
            ByteBuffer adminResponse = handleMessage(message, clientAddress);
            transport.sendMessage(adminResponse);
        } catch (Exception e) {
            transport.release();
            logger.error("Error occured while processing request:", e);
        }
    }

    private SaslServer sasl() throws Exception {
        CallbackHandler callbackHandler = new KerbySaslServer.SaslGssCallbackHandler();
        Map<String, Object> props = new HashMap<String, Object>();
        props.put(Sasl.QOP, "auth-conf");

        SaslServer ss = Sasl.createSaslServer("GSSAPI",
            "protocol", "localhost", props, callbackHandler);

        if (ss == null) {
            throw new Exception("Unable to find server implementation for: GSSAPI");
        }
        return ss;
    }

    private String getServerPrincipalName() {
        return "serverprincial";
    }

    private String getHostname() {
        return "localhost";
    }
}