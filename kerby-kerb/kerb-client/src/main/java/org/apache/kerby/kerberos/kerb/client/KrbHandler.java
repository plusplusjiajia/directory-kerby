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

import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.preauth.PreauthHandler;
import org.apache.kerby.kerberos.kerb.client.request.KdcRequest;
import org.apache.kerby.kerberos.kerb.spec.base.KrbMessage;
import org.apache.kerby.kerberos.kerb.spec.base.KrbMessageType;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcRep;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcReq;
import org.apache.kerby.kerberos.kerb.transport.KrbTransport;

import java.io.IOException;
import java.nio.ByteBuffer;

public abstract class KrbHandler {

    private PreauthHandler preauthHandler;

    public void init(KrbContext context) {
        preauthHandler = new PreauthHandler();
        preauthHandler.init(context);
    }

    public void handleRequest(KdcRequest kdcRequest) throws KrbException {
        kdcRequest.process();
        KdcReq kdcReq = kdcRequest.getKdcReq();
        int bodyLen = kdcReq.encodingLength();
        KrbTransport transport = (KrbTransport) kdcRequest.getSessionData();
        boolean isTcp = transport.isTcp();
        ByteBuffer requestMessage;

        if (!isTcp) {
            requestMessage = ByteBuffer.allocate(bodyLen);

        } else {
            requestMessage = ByteBuffer.allocate(bodyLen + 4);
            requestMessage.putInt(bodyLen);
        }
        kdcReq.encode(requestMessage);
        requestMessage.flip();
        try {
            sendMessage(kdcRequest, requestMessage);
        } catch (IOException e) {
            throw new KrbException("sending message failed", e);
        }
    }

    public void onResponseMessage(
            KdcRequest kdcRequest, ByteBuffer responseMessage) throws KrbException {

        KrbMessage kdcRep = null;
        try {
            kdcRep = KrbCodec.decodeMessage(responseMessage);
        } catch (IOException e) {
            throw new KrbException("Krb decoding message failed", e);
        }

        KrbMessageType messageType = kdcRep.getMsgType();
        if (messageType == KrbMessageType.AS_REP) {
            kdcRequest.processResponse((KdcRep) kdcRep);
        } else if (messageType == KrbMessageType.TGS_REP) {
            kdcRequest.processResponse((KdcRep) kdcRep);
        }
    }

    protected abstract void sendMessage(KdcRequest kdcRequest,
                                        ByteBuffer requestMessage) throws IOException;
}
