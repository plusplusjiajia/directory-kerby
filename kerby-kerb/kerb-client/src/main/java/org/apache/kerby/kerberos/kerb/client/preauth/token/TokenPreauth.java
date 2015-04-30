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
package org.apache.kerby.kerberos.kerb.client.preauth.token;

import org.apache.kerby.KOption;
import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.KrbRuntime;
import org.apache.kerby.kerberos.kerb.client.KrbContext;
import org.apache.kerby.kerberos.kerb.client.KrbOption;
import org.apache.kerby.kerberos.kerb.client.preauth.AbstractPreauthPlugin;
import org.apache.kerby.kerberos.kerb.client.request.KdcRequest;
import org.apache.kerby.kerberos.kerb.preauth.PaFlag;
import org.apache.kerby.kerberos.kerb.preauth.PaFlags;
import org.apache.kerby.kerberos.kerb.preauth.PluginRequestContext;
import org.apache.kerby.kerberos.kerb.preauth.token.TokenPreauthMeta;
import org.apache.kerby.kerberos.kerb.provider.TokenEncoder;
import org.apache.kerby.kerberos.kerb.spec.base.AuthToken;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.spec.base.KrbToken;
import org.apache.kerby.kerberos.kerb.spec.base.TokenFormat;
import org.apache.kerby.kerberos.kerb.spec.pa.PaData;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataType;
import org.apache.kerby.kerberos.kerb.spec.pa.token.PaTokenRequest;
import org.apache.kerby.kerberos.kerb.spec.pa.token.TokenInfo;

import java.util.Collections;
import java.util.List;

public class TokenPreauth extends AbstractPreauthPlugin {

    private TokenContext tokenContext;

    public TokenPreauth() {
        super(new TokenPreauthMeta());
    }

    public void init(KrbContext context) {
        super.init(context);
        this.tokenContext = new TokenContext();
    }

    @Override
    public PluginRequestContext initRequestContext(KdcRequest kdcRequest) {
        TokenRequestContext reqCtx = new TokenRequestContext();

        return reqCtx;
    }

    @Override
    public void prepareQuestions(KdcRequest kdcRequest,
                                 PluginRequestContext requestContext) {

    }

    @Override
    public List<EncryptionType> getEncTypes(KdcRequest kdcRequest,
                                            PluginRequestContext requestContext) {
        return Collections.emptyList();
    }

    @Override
    public void setPreauthOptions(KdcRequest kdcRequest,
                                  PluginRequestContext requestContext,
                                  KOptions options) {

        tokenContext.usingIdToken = options.getBooleanOption(KrbOption.USE_TOKEN);
        if (tokenContext.usingIdToken) {
            if (options.contains(KrbOption.TOKEN_USER_ID_TOKEN)) {
                tokenContext.token =
                        (AuthToken) options.getOptionValue(KrbOption.TOKEN_USER_ID_TOKEN);
            }
        } else {
            if (options.contains(KrbOption.TOKEN_USER_AC_TOKEN)) {
                tokenContext.token =
                        (AuthToken) options.getOptionValue(KrbOption.TOKEN_USER_AC_TOKEN);
            }
        }

    }

    public void tryFirst(KdcRequest kdcRequest,
                         PluginRequestContext requestContext,
                         PaData outPadata) throws KrbException {
        outPadata.addElement(makeEntry(kdcRequest));
    }

    @Override
    public boolean process(KdcRequest kdcRequest,
                           PluginRequestContext requestContext,
                           PaDataEntry inPadata,
                           PaData outPadata) throws KrbException {

        outPadata.addElement(makeEntry(kdcRequest));
        return true;
    }

    @Override
    public boolean tryAgain(KdcRequest kdcRequest,
                         PluginRequestContext requestContext,
                         PaDataType preauthType,
                         PaData errPadata,
                         PaData outPadata) {
        return false;
    }

    @Override
    public PaFlags getFlags(PaDataType paType) {
        PaFlags paFlags = new PaFlags(0);
        paFlags.setFlag(PaFlag.PA_REAL);

        return paFlags;
    }

    private PaDataEntry makeEntry(KdcRequest kdcRequest) throws KrbException {

        KOptions options = kdcRequest.getPreauthOptions();

        KOption option = options.getOption(KrbOption.TOKEN_USER_ID_TOKEN);
        AuthToken authToken = (AuthToken)option.getValue();

        TokenEncoder tokenEncoder = KrbRuntime.getTokenProvider().createTokenEncoder();

        KrbToken krbToken = new KrbToken();
        krbToken.setTokenValue(tokenEncoder.encodeAsBytes(authToken));
        krbToken.setTokenFormat(TokenFormat.JWT);
        PaTokenRequest tokenPa = new PaTokenRequest();
        tokenPa.setToken(krbToken);
        TokenInfo info = new TokenInfo();
        info.setTokenVendor("vendor");
        tokenPa.setTokenInfo(info);

        PaDataEntry paEntry = new PaDataEntry();
        paEntry.setPaDataType(PaDataType.TOKEN_REQUEST);
        paEntry.setPaDataValue(tokenPa.encode());

        return paEntry;
    }
}
