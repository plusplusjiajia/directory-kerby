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
package org.apache.kerby.kerberos.kerb.ap;

import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.keytab.Keytab;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.ap.ApOption;
import org.apache.kerby.kerberos.kerb.type.ap.ApRep;
import org.apache.kerby.kerberos.kerb.type.ap.ApReq;
import org.apache.kerby.kerberos.kerb.type.ap.Authenticator;
import org.apache.kerby.kerberos.kerb.type.ap.EncAPRepPart;
import org.apache.kerby.kerberos.kerb.type.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.KeyUsage;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.ticket.EncTicketPart;
import org.apache.kerby.kerberos.kerb.type.ticket.Ticket;

import java.io.File;
import java.io.IOException;


public class ApResponse {
    private ApReq apReq;
    private ApRep apRep;
    private File keytabFile;
    private Keytab keytab;
    public ApResponse(ApReq apReq, File keyTabFile) {
        this.apReq = apReq;
        this.keytabFile = keyTabFile;

        // Load Keytab File
        try {
            keytab =  Keytab.loadKeytab(keytabFile);
        } catch (IOException e) {
            System.err.println("Can not load keytab from file" + keytabFile.getAbsolutePath());
        }
    }

    public ApRep getApRep() throws KrbException {
        ApRequest.validate(keytab, apReq);

        if (apRep == null) {
            apRep = makeApRep();
        }
        return apRep;
    }

    public void setApRep(ApRep apRep) {
        this.apRep = apRep;
    }

    /*
     *  The KRB_AP_REP message contains the Kerberos protocol version number,
     *  the message type, and an encrypted time-stamp.
     */
    private ApRep makeApRep() throws KrbException {

        ApRep apRep = new ApRep();
        EncAPRepPart encAPRepPart = new EncAPRepPart();
        // This field contains the current time on the client's host.
        encAPRepPart.setCtime(KerberosTime.now());
        // This field contains the microsecond part of the client's timestamp.
        encAPRepPart.setCusec((int) KerberosTime.now().getTimeInSeconds());
        encAPRepPart.setSubkey(apReq.getAuthenticator().getSubKey());
        encAPRepPart.setSeqNumber(0);
        apRep.setEncRepPart(encAPRepPart);
        EncryptedData encPart = EncryptionUtil.seal(encAPRepPart,
                apReq.getAuthenticator().getSubKey(), KeyUsage.AP_REP_ENCPART);
        apRep.setEncryptedEncPart(encPart);

        return apRep;
    }


}
