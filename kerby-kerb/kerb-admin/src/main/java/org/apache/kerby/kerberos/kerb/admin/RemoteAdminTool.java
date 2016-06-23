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
package org.apache.kerby.kerberos.kerb.admin;

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.KadminOption;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminClient;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminConfig;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminUtil;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.command.RemoteAddPrincipalCommand;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.command.RemoteCommand;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.command.RemoteDeletePrincipalCommand;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.command.RemoteGetprincsCommand;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.command.RemotePrintUsageCommand;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.command.RemoteRenamePrincipalCommand;
import org.apache.kerby.kerberos.kerb.admin.kadmin.sasl.AuthUtil;
import org.apache.kerby.kerberos.kerb.common.KrbUtil;
import org.apache.kerby.kerberos.kerb.server.KdcConfig;
import org.apache.kerby.kerberos.kerb.server.KdcUtil;
import org.apache.kerby.kerberos.kerb.transport.KrbNetwork;
import org.apache.kerby.kerberos.kerb.transport.KrbTransport;
import org.apache.kerby.kerberos.kerb.transport.TransportPair;
import org.apache.kerby.util.OSUtil;

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
import java.util.Map;
import java.util.Scanner;

/**
 * Command use of remote admin
 */
public class RemoteAdminTool {
    private static final byte[] EMPTY = new byte[0];
    private static KrbTransport transport;
    private static final String PROMPT = RemoteAdminTool.class.getSimpleName() + ".local:";
    private static final String USAGE = (OSUtil.isWindows()
        ? "Usage: bin\\remoteAdmin.cmd" : "Usage: sh bin/remoteAdmin.sh")
        + " <conf-file>\n"
        + "\tExample:\n"
        + "\t\t"
        + (OSUtil.isWindows()
        ? "bin\\remoteAdmin.cmd" : "sh bin/remoteAdmin.sh")
        + " conf\n";

    private static final String LEGAL_COMMANDS = "Available commands are: "
        + "\n"
        + "add_principal, addprinc\n"
        + "                         Add principal\n"
        + "delete_principal, delprinc\n"
        + "                         Delete principal\n"
        + "rename_principal, renprinc\n"
        + "                         Rename principal\n"
        + "listprincs\n"
        + "          List principals\n";

    public static void main(String[] args) throws Exception {
        AdminClient adminClient;

        if (args.length < 1) {
            System.err.println(USAGE);
            System.exit(1);
        }

        String confDirPath = args[0];

        File confFile = new File(confDirPath, "adminClient.conf");

        AdminConfig adminConfig = new AdminConfig();
        adminConfig.addKrb5Config(confFile);

        KdcConfig tmpKdcConfig = KdcUtil.getKdcConfig(new File(confDirPath));
        if (tmpKdcConfig == null) {
            tmpKdcConfig = new KdcConfig();
        }

        try {
            Krb5Conf krb5Conf = new Krb5Conf(new File(confDirPath), tmpKdcConfig);
            krb5Conf.initKrb5conf();
        } catch (IOException e) {
            throw new KrbException("Failed to make krb5.conf", e);
        }

        adminClient = new AdminClient(adminConfig);

        KOptions kOptions = ToolUtil.parseOptions(args, 1, args.length - 1);
        if (kOptions.contains(KadminOption.K)) {
            File keyTabFile = new File(kOptions.getStringOption(KadminOption.K));
            if (keyTabFile == null || !keyTabFile.exists()) {
                System.err.println("Need the valid keytab file.");
                return;
            }
            adminClient.setKeyTabFile(keyTabFile);
        }


        String adminRealm = adminConfig.getAdminRealm();

        adminClient.setAdminRealm(adminRealm);
        adminClient.setAllowTcp(true);
        adminClient.setAllowUdp(false);
        adminClient.setAdminTcpPort(adminConfig.getAdminPort());

        adminClient.init();
        System.out.println("admin init successful");


        TransportPair tpair = null;
        try {
            tpair = AdminUtil.getTransportPair(adminClient.getSetting());
        } catch (KrbException e) {
            e.printStackTrace();
        }
        KrbNetwork network = new KrbNetwork();
        network.setSocketTimeout(adminClient.getSetting().getTimeout());

        try {
            transport = network.connect(tpair);
        } catch (IOException e) {
            throw new KrbException("Failed to create transport", e);
        }


        String adminPrincipal = KrbUtil.makeKadminPrincipal(
            adminClient.getSetting().getKdcRealm()).getName();
        Subject subject = null;
        try {
            subject = AuthUtil.loginUsingKeytab(adminPrincipal,
                adminClient.getSetting().getKeyTabFile());
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

        System.out.println("enter \"command\" to see legal commands.");

        try (Scanner scanner = new Scanner(System.in, "UTF-8")) {
            String input = scanner.nextLine();

            while (!(input.equals("quit") || input.equals("exit") || input.equals("q"))) {
                excute(adminClient, input);
                System.out.print(PROMPT);
                input = scanner.nextLine();
            }
        }

    }

    private static void excute(AdminClient adminClient, String input) throws KrbException {
        input = input.trim();
        if (input.startsWith("command")) {
            System.out.println(LEGAL_COMMANDS);
            return;
        }

        RemoteCommand executor = null;

        if (input.startsWith("add_principal")
            || input.startsWith("addprinc")) {
            executor = new RemoteAddPrincipalCommand(adminClient);
        } else if (input.startsWith("delete_principal")
            || input.startsWith("delprinc")) {
            executor = new RemoteDeletePrincipalCommand(adminClient);
        } else if (input.startsWith("rename_principal")
            || input.startsWith("renprinc")) {
            executor = new RemoteRenamePrincipalCommand(adminClient);
        } else if (input.startsWith("list_principals")) {
            executor = new RemoteGetprincsCommand(adminClient);
        } else if (input.startsWith("listprincs")) {
            executor = new RemotePrintUsageCommand();
        } else {
            System.out.println(LEGAL_COMMANDS);
            return;
        }
        executor.execute(input);
    }


}
