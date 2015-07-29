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

import org.apache.kerby.KOption;
import org.apache.kerby.KOptionType;
import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.AdminHelper;
import org.apache.kerby.kerberos.kerb.admin.Kadmin;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.server.KdcConfig;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionType;

import java.io.Console;
import java.io.File;
import java.util.Arrays;

public class KdcInitTool {
    private Kadmin kadmin;
    private static File confDir;
    private static File keytabFile;
    private static File stashFile;

    private static final String USAGE = "Usage: " +
        KdcInitTool.class.getSimpleName() +
        " -c conf-dir -keytab keytab";

    private void init(File confDir, KOptions kOptions) throws KrbException {
        kadmin = new Kadmin(confDir);
        createMasterKey(kOptions);
        kadmin.createBuiltinPrincipals();
        kadmin.exportKeytab(keytabFile, kadmin.getKadminPrincipal());
        System.out.println("The kadmin principal " + kadmin.getKadminPrincipal()
                + " has exported into keytab file " + keytabFile.getAbsolutePath()
                + ", please make sure to keep it, because it will be used by kadmin tool"
                + " for the authentication.");
    }

    private static void printUsage(String error) {
        System.err.println(error + "\n");
        System.err.println(USAGE);
        System.exit(-1);
    }

    private void createMasterKey(KOptions kOptions) throws KrbException {

        System.out.println("master key name: " + kadmin.getMasterPrincipal());

        System.out.println(
                "You will be prompted for the database Master Password.\n" +
                "It is important that you NOT FORGET this password.");

        String masterPrincipal = kadmin.getMasterPrincipal();
        KdcConfig kdcConfig = kadmin.getKdcConfig();
        EncryptionType masterKeyType = null;
        if (kOptions.contains(KdcInitOption.MASTER_KEY_TYPE)) {
            masterKeyType = EncryptionType.fromName(
                    kOptions.getStringOption(KdcInitOption.MASTER_KEY_TYPE));
        } else {
            masterKeyType = EncryptionType.fromName(kdcConfig.getMasterKeyType());
        }
        if(kOptions.contains(KdcInitOption.STASH_FILE_NAME)) {
            stashFile = kOptions.getFileOption(KdcInitOption.STASH_FILE_NAME);
        } else {
            stashFile = new File(kdcConfig.getKeyStashFile());
        }
        String password = getPassword();
        if (password == null) {
            System.out.println("Did not get new password successfully. Please try again");
            return;
        }
        KrbIdentity identity = kadmin.createMasterKeyIdentity(masterPrincipal, password, masterKeyType);
        AdminHelper.exportKeytab(stashFile, identity);
    }

    /**
     * Get password from console
     */
    private String getPassword() {
        String passwordOnce;
        String passwordTwice;

        Console console = System.console();
        passwordOnce = getPassword(console,
                "Please enter KDC database master key:");
        passwordTwice = getPassword(console,
                "Please re-enter database master key to verify:");

        if (!passwordOnce.equals(passwordTwice)) {
            System.err.println("Password mismatch while reading master key from keyboard.");
            return null;
        }
        return passwordOnce;
    }

    private String getPassword(Console console, String prompt) {
        console.printf(prompt);
        char[] passwordChars = console.readPassword();
        String password = new String(passwordChars).trim();
        Arrays.fill(passwordChars, ' ');
        return password;
    }

    public static void main(String[] args) throws KrbException {
//        if (args.length != 2) {
//            System.err.println(USAGE);
//            System.exit(1);
//        }

        KOptions kOptions = parseOptions(args, 0, args.length - 1);
        if (kOptions == null) {
            System.err.println(USAGE);
            return;
        }

        if (kOptions.contains(KdcInitOption.CONF_DIR)) {
            confDir = kOptions.getDirOption(KdcInitOption.CONF_DIR);
            if (!confDir.exists()) {
                printUsage("Invalid or not exist conf-dir.");
                System.exit(2);
            }
        }
        if(kOptions.contains(KdcInitOption.KEYTAB)) {
            keytabFile = kOptions.getFileOption(KdcInitOption.KEYTAB);
            File keytabFilePath = keytabFile.getParentFile();
            if (keytabFilePath != null && !keytabFilePath.exists() && !keytabFilePath.mkdirs()) {
                System.err.println("Could not create keytab path." + keytabFilePath);
                System.exit(3);
            }

            if (keytabFile.exists()) {
                System.err.println("There is one kadmin keytab exists in " +
                        keytabFilePath.getAbsolutePath() +
                        ", this tool maybe have been executed, if not," +
                        " please delete it or change the keytab-dir.");
                return;
            }
        }

        KdcInitTool kdcInitTool = new KdcInitTool();
        System.out.println("Initializing kdc.");

        try {
            kdcInitTool.init(confDir, kOptions);
        } catch (KrbException e) {
          System.err.println("Errors occurred when init the kdc " + e.getMessage());
          return;
        }

        System.out.println("Finish kdc init.");
    }

    public static KOptions parseOptions(String[] commands, int beginIndex, int endIndex) {
        KOption kOption;
        String opt, error, param;

        if (beginIndex < 0) {
            System.out.println("Invalid function parameter(s).");
            return null;
        }

        KOptions kOptions = new KOptions();
        int i = beginIndex;
        while (i <= endIndex) {
            error = null;
            opt = commands[i++];
            if (opt.startsWith("-")) {
                kOption = KdcInitOption.fromName(opt);
                if (kOption == KdcInitOption.NONE) {
                    error = "Invalid option:" + opt;
                }
            } else {
                kOption = KdcInitOption.NONE;
                error = "Invalid parameter:" + opt + " , it does not belong to any option.";
            }

            if (kOption.getType() != KOptionType.NOV) { // require a parameter
                param = null;
                if (i <= endIndex) {
                    param = commands[i++];
                }
                if (param != null) {
                    kOptions.parseSetValue(kOption, param);
                } else {
                    error = "Option " + opt + " require a parameter";
                }
            }
            if (error != null) {
                System.out.println(error);
                return null;
            }
            kOptions.add(kOption);
        }
        return kOptions;
    }

}
