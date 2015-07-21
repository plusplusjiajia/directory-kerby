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

import java.io.File;

public class KdcInitTool {
    private Kadmin kadmin;
    private static File keytabFile;

    private static final String USAGE = "Usage: " +
        KdcInitTool.class.getSimpleName() +
        " conf-dir keytab";

    public void init(File confDir) throws KrbException {
        kadmin = new Kadmin(confDir);
        kadmin.createBuiltinPrincipals();
        kadmin.exportKeytab(keytabFile, kadmin.getKadminPrincipal());
        System.out.println("The kadmin principal " + kadmin.getKadminPrincipal() +
                " has exported into keytab file " + keytabFile.getAbsolutePath() +
                ", please make sure to keep it, because it will be used by kadmin tool" +
                " for the authentication.");
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
        if (keytabFilePath != null) {
            if (!keytabFilePath.exists() && !keytabFilePath.mkdirs()) {
                System.err.println("Could not create keytab path." + keytabFilePath);
                System.exit(3);
            }
        } else {
            System.err.println("Please give the absolute path of keytab file.");
            System.exit(4);
        }

        if (keytabFile.exists()) {
            System.err.println("There is one kadmin keytab exists in " + keyTabPath +
                ", this tool maybe have been executed, if not," +
                " please delete it or change the keytab-dir.");
            return;
        }

        KdcInitTool kdcInitTool = new KdcInitTool();

        try {
            kdcInitTool.init(confDir);
        } catch (KrbException e) {
          System.err.println("Errors occurred when init the kdc " + e.getMessage());
          return;
        }

        System.out.println("Finish kdc init.");
    }
}
