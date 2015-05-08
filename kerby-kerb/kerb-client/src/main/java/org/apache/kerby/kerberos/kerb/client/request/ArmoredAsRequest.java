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
package org.apache.kerby.kerberos.kerb.client.request;

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.ccache.Credential;
import org.apache.kerby.kerberos.kerb.ccache.CredentialCache;
import org.apache.kerby.kerberos.kerb.client.KrbContext;
import org.apache.kerby.kerberos.kerb.client.KrbOption;
import org.apache.kerby.kerberos.kerb.client.preauth.KrbCredsContext;
import org.apache.kerby.kerberos.kerb.client.preauth.KrbFastRequestState;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.crypto.fast.FastUtil;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.ap.ApOptions;
import org.apache.kerby.kerberos.kerb.spec.ap.ApReq;
import org.apache.kerby.kerberos.kerb.spec.ap.Authenticator;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.spec.fast.ArmorType;
import org.apache.kerby.kerberos.kerb.spec.fast.KrbFastArmor;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcReq;
import org.apache.kerby.kerberos.kerb.spec.ticket.Ticket;

import java.io.File;
import java.io.IOException;

/**
 * This initiates an armor protected AS-REQ using FAST/Pre-auth.
 */
public abstract class ArmoredAsRequest extends AsRequest {

    private Credential credential;

    public ArmoredAsRequest(KrbContext context) {
        super(context);
    }

    @Override
    public KOptions getPreauthOptions() {
        KOptions results = new KOptions();

        KOptions krbOptions = getKrbOptions();
        results.add(krbOptions.getOption(KrbOption.ARMOR_CACHE));

        return results;
    }

    @Override
    public EncryptionKey getClientKey() throws KrbException {
        return makeArmorKey() ;
    }

    /**
     * Prepare FAST armor key.
     * @return
     * @throws KrbException
     */
    public EncryptionKey makeArmorKey() throws KrbException {
        getCredential();

        EncryptionKey armorCacheKey = getArmorCacheKey();
        EncryptionKey subKey = getSubKey(armorCacheKey.getKeyType());
        EncryptionKey armorKey = FastUtil.cf2(subKey, "subkeyarmor", armorCacheKey, "ticketarmor");

        KrbFastRequestState state = getFastRequestState();
        state.setArmorKey(armorKey);
        state.setFastArmor(fastArmorApRequest(subKey));
        KdcReq fastOuterRequest = getKdcReq();
//        fastOuterRequest.setPaData(null);
        state.setFastOuterRequest(getKdcReq());
//        ctx.setFastFlags();
//        ctx.setFastOptions();
//        ctx.setNonce();
        setFastRequestState(state);

        KrbCredsContext ctx = getCredsContext();
        ctx.setFastRequestState(state);
//        ctx.setOuterRequestBody(fastOuterRequest.encode());
        setCredsContext(ctx);

        return armorKey;
    }

    public KrbFastArmor fastArmorApRequest(EncryptionKey subKey) throws KrbException {
        KrbFastArmor fastArmor = new KrbFastArmor();
        fastArmor.setArmorType(ArmorType.ARMOR_AP_REQUEST);
        ApReq apReq = makeApReq(subKey);
        fastArmor.setArmorValue(apReq.encode());
        return fastArmor;
    }

    private ApReq makeApReq(EncryptionKey subKey) throws KrbException {
        ApReq apReq = new ApReq();
        ApOptions apOptions = new ApOptions();
        apReq.setApOptions(apOptions);
        Ticket ticket = credential.getTicket();
        apReq.setTicket(ticket);
        Authenticator authenticator = makeAuthenticator(subKey);
        apReq.setAuthenticator(authenticator);
//        EncryptedData authnData = EncryptionUtil.seal(authenticator,
//            credential.getKey(), KeyUsage.AP_REQ_AUTH);
//        apReq.setEncryptedAuthenticator(authnData);
        return apReq;
    }

    private Authenticator makeAuthenticator(EncryptionKey subKey) throws KrbException {
        Authenticator authenticator = new Authenticator();
        authenticator.setCname(credential.getClientName());
        authenticator.setCrealm(credential.getClientRealm());

        authenticator.setCtime(KerberosTime.now());
        authenticator.setCusec(0);

        authenticator.setSubKey(subKey);

        return authenticator;
    }


    protected EncryptionKey getSubKey(EncryptionType type) throws KrbException {
        return EncryptionHandler.random2Key(type);
    }

    /**
     * Get armor cache key.
     * @return armor cache key
     * @throws KrbException
     */
    protected EncryptionKey getArmorCacheKey() throws KrbException {
        EncryptionKey armorCacheKey = credential.getKey();

        return armorCacheKey;
    }

    private void getCredential() throws KrbException {
        KOptions preauthOptions = getPreauthOptions();
        String ccache = preauthOptions.getStringOption(KrbOption.ARMOR_CACHE);
        File ccacheFile = new File(ccache);
        CredentialCache cc = null;
        try {
            cc = resolveCredCache(ccacheFile);
        } catch (IOException e) {
            throw new KrbException("Failed to load armor cache file");
        }
//        Iterator<Credential> iterator = cc.getCredentials().iterator();
//        iterator.next();
//        iterator.next();
//        this.credential = iterator.next();
        this.credential = cc.getCredentials().iterator().next();
    }
}
