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
package org.apache.kerby.kerberos.kerb.admin.kadmin.remote;

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.Kadmin;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.impl.DefaultAdminHandler;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.impl.InternalAdminClient;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.request.AddPrincipalRequest;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.request.AdminRequest;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.request.DeletePrincipalRequest;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.request.GetprincsRequest;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.request.RenamePrincipalRequest;
import org.apache.kerby.kerberos.kerb.admin.kadmin.sasl.AuthUtil;
import org.apache.kerby.kerberos.kerb.common.KrbUtil;
import org.apache.kerby.kerberos.kerb.transport.KrbNetwork;
import org.apache.kerby.kerberos.kerb.transport.KrbTransport;
import org.apache.kerby.kerberos.kerb.transport.TransportPair;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.PrivilegedAction;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Server side admin facilities from remote, similar to MIT Kadmin remote mode.
 * It uses GSSAPI and XDR to communicate with remote KDC/kadmind to do the
 * requested operations. In the client side, it simply wraps and sends the
 * request info to the admin kadmind side, and then unwraps the response for
 * the operation result.
 *
 * TO BE IMPLEMENTED.
 */
public class RemoteKadminImpl implements Kadmin {

    private InternalAdminClient innerClient;
    private KrbTransport transport;
    private static final byte[] EMPTY = new byte[0];

    public RemoteKadminImpl(InternalAdminClient innerClient) throws KrbException {
        this.innerClient = innerClient;
        TransportPair tpair = null;
        try {
            tpair = AdminUtil.getTransportPair(innerClient.getSetting());
        } catch (KrbException e) {
            e.printStackTrace();
        }
        KrbNetwork network = new KrbNetwork();
        network.setSocketTimeout(innerClient.getSetting().getTimeout());
        try {
            transport = network.connect(tpair);
        } catch (IOException e) {
            throw new KrbException("Failed to create transport", e);
        }

        Subject subject = null;
        try {
            subject = AuthUtil.loginUsingKeytab(getKadminPrincipal(),
                innerClient.getSetting().getKeyTabFile());
        } catch (LoginException e) {
            e.printStackTrace();
        }
        Subject.doAs(subject, new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                try {

                    Map<String, String> props = new HashMap<String, String>();
                    props.put(Sasl.QOP, "auth-conf");
//        props.put(Sasl.SERVER_AUTH, "true");
//        props.put("com.sun.security.sasl.digest.cipher", "rc4");
                    SaslClient saslClient = null;
                    try {
                        saslClient = Sasl.createSaslClient(new String[]{"GSSAPI"}, null,
                            "test", "localhost", props, null);

                    } catch (SaslException e) {
                        e.printStackTrace();
                    }
                    if (saslClient == null) {
                        throw new KrbException("Unable to find client implementation for: GSSAPI");
                    }
                    byte[] response = new byte[0];
                    try {
                        response = saslClient.hasInitialResponse()
                            ? saslClient.evaluateChallenge(EMPTY) : EMPTY;
                    } catch (SaslException e) {
                        e.printStackTrace();
                    }
//        logger.info("initial: " + new String(response));
                    ByteBuffer buffer = ByteBuffer.allocate(response.length + 8); // 4 is the head to go through network
                    buffer.putInt(response.length+4);
                    int scComplete = saslClient.isComplete() ? 0 : 1;
                    buffer.putInt(scComplete);
                    buffer.put(response);
                    buffer.flip();
                    System.out.println("###send message length:"+response.length);
//                    System.out.println("###client send token:" + new String(response));
                    try {
                        transport.sendMessage(buffer);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    System.out.println("###send to remote kadmin server.");
                    ByteBuffer message = transport.receiveMessage();

                    while (!saslClient.isComplete()) {
                        int ssComplete = message.getInt();
                        System.out.println("complete?:" + ssComplete);
                        byte[] arr = new byte[message.remaining()];
                        message.get(arr);
                        System.out.println("###received message length:" + arr.length);
//                    System.out.println("###server received token:" + new String(arr));
                        byte[] challenge = saslClient.evaluateChallenge(arr);
                        System.out.println("saslClientcomplete??"+saslClient.isComplete());

                        ByteBuffer buffer1 = ByteBuffer.allocate(challenge.length + 8); // 4 is the head to go through network
                        buffer1.putInt(challenge.length + 4);
                        int scComplete1 = saslClient.isComplete() ? 0 : 1;

                        System.out.println("scComplete?" + scComplete1);
                        buffer1.putInt(scComplete1);
                        buffer1.put(challenge);
                        buffer1.flip();
                        System.out.println("###send message length:" + challenge.length);
//                    System.out.println("###client send token:" + new String(response));
                        try {
                            transport.sendMessage(buffer1);
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                        System.out.println("###send to remote kadmin server.");
                        if (!saslClient.isComplete()) {
                            message = transport.receiveMessage();
                        }
                    }

                } catch (Exception e) {
                    e.printStackTrace();
                }
                return null;
            }
        });

    }

    public InternalAdminClient getInnerClient() {
        return innerClient;
    }


    @Override
    public String getKadminPrincipal() {
//        String name = innerClient.getSetting().getAdminConfig().getAdminHost();
//        return name;
        return KrbUtil.makeKadminPrincipal(innerClient.getSetting().getKdcRealm()).getName();
    }

    @Override
    public void addPrincipal(String principal) throws KrbException {
        //generate an admin request
        AdminRequest adRequest = new AddPrincipalRequest(principal);
        adRequest.setTransport(transport);
        //handle it
        AdminHandler adminHandler = new DefaultAdminHandler();
        adminHandler.handleRequest(adRequest);

    }

    @Override
    public void addPrincipal(String principal,
                             KOptions kOptions) throws KrbException {
        AdminRequest adRequest = new AddPrincipalRequest(principal, kOptions);
        //wrap buffer problem
        adRequest.setTransport(transport);
        AdminHandler adminHandler = new DefaultAdminHandler();
        adminHandler.handleRequest(adRequest);
    }

    @Override
    public void addPrincipal(String principal,
                             String password) throws KrbException {
        AdminRequest addPrincipalRequest = new AddPrincipalRequest(principal, password);
        addPrincipalRequest.setTransport(transport);
        AdminHandler adminHandler = new DefaultAdminHandler();
        adminHandler.handleRequest(addPrincipalRequest);
    }

    @Override
    public void addPrincipal(String principal, String password,
                             KOptions kOptions) throws KrbException {

    }

    @Override
    public void exportKeytab(File keytabFile,
                             String principal) throws KrbException {

    }

    @Override
    public void exportKeytab(File keytabFile,
                             List<String> principals) throws KrbException {

    }

    @Override
    public void exportKeytab(File keytabFile) throws KrbException {

    }

    @Override
    public void removeKeytabEntriesOf(File keytabFile,
                                      String principal) throws KrbException {

    }

    @Override
    public void removeKeytabEntriesOf(File keytabFile, String principal,
                                      int kvno) throws KrbException {

    }

    @Override
    public void removeOldKeytabEntriesOf(File keytabFile,
                                         String principal) throws KrbException {

    }

    @Override
    public void deletePrincipal(String principal) throws KrbException {
        AdminRequest deletePrincipalRequest = new DeletePrincipalRequest(principal);
        deletePrincipalRequest.setTransport(transport);
        AdminHandler adminHandler = new DefaultAdminHandler();
        adminHandler.handleRequest(deletePrincipalRequest);
    }

    @Override
    public void modifyPrincipal(String principal,
                                KOptions kOptions) throws KrbException {

    }

    @Override
    public void renamePrincipal(String oldPrincipalName,
                                String newPrincipalName) throws KrbException {
        AdminRequest renamePrincipalRequest =  new RenamePrincipalRequest(oldPrincipalName, newPrincipalName);
        renamePrincipalRequest.setTransport(transport);
        AdminHandler adminHandler = new DefaultAdminHandler();
        adminHandler.handleRequest(renamePrincipalRequest);
    }

    @Override
    public List<String> getPrincipals() throws KrbException {
        AdminRequest grtPrincsRequest = new GetprincsRequest();
        grtPrincsRequest.setTransport(transport);
        AdminHandler adminHandler = new DefaultAdminHandler();
        return adminHandler.handleRequestForList(grtPrincsRequest);
    }

    @Override
    public List<String> getPrincipals(String globString) throws KrbException {
        AdminRequest grtPrincsRequest = new GetprincsRequest(globString);
        grtPrincsRequest.setTransport(transport);
        AdminHandler adminHandler = new DefaultAdminHandler();
        return adminHandler.handleRequestForList(grtPrincsRequest);
    }

    @Override
    public void changePassword(String principal,
                               String newPassword) throws KrbException {

    }

    @Override
    public void updateKeys(String principal) throws KrbException {

    }

    @Override
    public void release() throws KrbException {

    }
}
