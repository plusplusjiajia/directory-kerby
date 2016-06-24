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
package org.apache.kerby.kerberos.tool.kdcinit;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadmin;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadminImpl;
import org.apache.kerby.kerberos.kerb.admin.server.kadmin.AdminServer;
import org.apache.kerby.kerberos.kerb.admin.server.kadmin.AdminServerConfig;
import org.apache.kerby.util.OSUtil;

import java.io.File;

/**
 * A tool to initialize KDC backend for the first time when setup the KDC.
 */
public class KdcInitTool {
    private LocalKadmin kadmin;
    private static File keytabFile;

    private static  final String USAGE = (OSUtil.isWindows()
            ? "Usage: bin\\kdcinit.cmd" : "Usage: sh bin/kdcinit.sh")
            + " <conf-dir> <output-keytab>\n"
            + "\tThis tool initializes KDC backend and should only be performed the first time,\n"
            + "\tand the output keytab should be carefully kept to administrate/kadmin KDC later.\n"
            + "\tExample:\n"
            + "\t\t"
            + (OSUtil.isWindows()
            ? "bin\\kdcinit.cmd" : "sh bin/kdcinit.sh")
            + " conf admin.keytab\n";

    void initKdc(File confDir) throws KrbException {
        kadmin = new LocalKadminImpl(confDir);
        try {
            kadmin.createBuiltinPrincipals();
            kadmin.exportKeytab(keytabFile, kadmin.getKadminPrincipal());
            System.out.println("The keytab for kadmin principal "
                    + " has been exported to the specified file "
                    + keytabFile.getAbsolutePath() + ", please safely keep it, "
                    + "in order to use kadmin tool later");

            // Export protocol keytab file
            AdminServer adminServer = new AdminServer(confDir);
            AdminServerConfig adminServerConfig = adminServer.getAdminServerConfig();
            String principal = adminServerConfig.getProtocol() + "/"
                + adminServerConfig.getAdminHost() + "@" + adminServerConfig.getAdminRealm();
            kadmin.addPrincipal(principal);
            kadmin.exportKeytab(new File("protocol.keytab"), principal);
        } finally {
            kadmin.release();
        }
    }

    public static void main(String[] args) throws KrbException {
        if (args.length != 2) {
            System.err.println(USAGE);
            System.exit(1);
        }

        String confDirPath = args[0];
        String keyTabPath = args[1];
        File confDir = new File(confDirPath);
        keytabFile = new File(keyTabPath);
        if (!confDir.exists()) {
            System.err.println("Invalid or not exist conf-dir.");
            System.exit(2);
        }
        File keytabFilePath = keytabFile.getParentFile();
        if (keytabFilePath != null && !keytabFilePath.exists() && !keytabFilePath.mkdirs()) {
            System.err.println("Could not create keytab path." + keytabFilePath);
            System.exit(3);
        }

        if (keytabFile.exists()) {
            System.err.println("The kadmin keytab already exists in " + keyTabPath
                    + ", this tool maybe have been executed already.");
            return;
        }

        KdcInitTool kdcInitTool = new KdcInitTool();

        try {
            kdcInitTool.initKdc(confDir);
        } catch (KrbException e) {
            System.err.println("Errors occurred when init the kdc " + e.getMessage());
            System.exit(1);
        }

        System.out.println("Finished initializing the KDC backend");
        System.exit(0);
    }
}
