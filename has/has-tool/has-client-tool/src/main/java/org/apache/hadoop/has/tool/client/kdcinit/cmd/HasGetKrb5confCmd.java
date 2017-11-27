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
package org.apache.hadoop.has.tool.client.kdcinit.cmd;

import org.apache.hadoop.has.client.HasAdminClient;
import org.apache.kerby.kerberos.kerb.KrbException;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;

/**
 * Remote get krb5.conf cmd
 */
public class HasGetKrb5confCmd extends KdcInitCmd {

    public static final String USAGE = "Usage: get_krb5conf [-p] [path]\n"
        + "\tExample:\n"
        + "\t\tget_krb5conf -p /tmp/has\n";

    public HasGetKrb5confCmd(HasAdminClient hadmin) {
        super(hadmin);
    }

    @Override
    public void execute(String[] items) throws KrbException {
        if (items.length >= 2) {
            if (items[1].startsWith("?") || items[1].startsWith("-help")) {
                System.out.println(USAGE);
                return;
            }
        }
        File path = getHadmin().getConfDir();
        if (items.length >= 3 && items[1].startsWith("-p")) {
            path = new File(items[2]);
            if (!path.exists()) {
                if (!path.mkdirs()) {
                    System.err.println("Cannot create file : " + items[2]);
                    return;
                }
            }
        }
        File krb5Conf = new File(path, "krb5.conf");

        HasAdminClient hasAdminClient = getHadmin();
        String content = hasAdminClient.getKrb5conf();
        if (content == null) {
            System.err.println("Failed to get krb5.conf.");
            return;
        }
        try {
            PrintStream ps = new PrintStream(new FileOutputStream(krb5Conf));
            ps.println(content);
            System.out.println("krb5.conf has saved in : " + krb5Conf.getAbsolutePath());
        } catch (FileNotFoundException e) {
            System.err.println(e.getMessage());
        }
    }
}