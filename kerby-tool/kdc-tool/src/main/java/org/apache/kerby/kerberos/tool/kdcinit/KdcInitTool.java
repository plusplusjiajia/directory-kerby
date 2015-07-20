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
import org.apache.kerby.kerberos.kerb.admin.Kadmin;
import org.apache.kerby.kerberos.kerb.server.KdcServer;

import java.io.File;

public class KdcInitTool extends KdcServer {
    private Kadmin kadmin;
    private static File keytabFile;

    private static final String USAGE = "Usage: " +
        KdcInitTool.class.getSimpleName() +
        " conf-dir keytab-dir";

    public KdcInitTool(File confDir) throws KrbException {
        super(confDir);

    }

    @Override
    public void init() throws KrbException {
        super.init();

        kadmin = new Kadmin(getKdcSetting(), getIdentityService());
        kadmin.createBuiltinPrincipals();
        kadmin.exportKeytab(keytabFile, kadmin.getKadminPrincipal());
        System.out.println("The kadmin principal " + kadmin.getKadminPrincipal()
            + " has exported into keytab file " + keytabFile.getAbsolutePath()
            + ", please make sure to keep it.");
    }

    public static void main(String[] args) throws KrbException {
        if (args.length != 2) {
            System.err.println(USAGE);
            System.exit(1);
        }

        String confDirPath = args[0];
        String keyTabPath = args[1];
        File confDir = new File(confDirPath);
        File keytabDir = new File(keyTabPath);
        if (!confDir.exists() || !keytabDir.exists()) {
            System.err.println("Invalid or not exist conf-dir or keytab-dir.");
            System.exit(3);
        }

        keytabFile = new File(keytabDir, "kadmin.keytab");

        if (keytabFile.exists()) {
            System.err.println("There is one kadmin.keytab exsits," +
                " this tool maybe have executed, if not," +
                " please delete it or change the kertab-dir.");
            return;
        }

        KdcInitTool kdcInitTool = new KdcInitTool(confDir);

        try {
            kdcInitTool.init();
        } catch (KrbException e) {
          System.err.println("Errors occurred when init the kdc " + e.getMessage());
          return;
        }

        System.out.println("Finish kdc init.");
    }
}
