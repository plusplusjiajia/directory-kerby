package org.apache.kerby.kerberos.kerb.client.preauth;

import org.apache.kerby.kerberos.kerb.spec.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcRep;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcReq;

public class KrbCredsContext {

    private KrbFastRequestState fastRequestState;
    private KdcReq request;
    private KdcRep reply;
    private byte[] outerRequestBody;
    private byte[] innerRequestBody;
    private byte[] encodedPreviousRequest;
    private EncryptionType encryptionType;
    private boolean preauthRequired;

    public KrbFastRequestState getKrbFastRequestState() {
        return fastRequestState;
    }

    public void setFastRequestState(KrbFastRequestState state) {
        this.fastRequestState = state;
    }

    public KdcReq getRequest() {
        return request;
    }

    public void setRequest(KdcReq request) {
        this.request = request;
    }

    public KdcRep getReply() {
        return reply;
    }

    public void setReply(KdcRep reply) {
        this.reply = reply;
    }

    public byte[] getOuterRequestBody() {
        return outerRequestBody;
    }

    public void setOuterRequestBody(byte[] outerRequestBody) {
        this.outerRequestBody = outerRequestBody;
    }

    public byte[] getInnerRequestBody() {
        return innerRequestBody;
    }

    public void setInnerRequestBody(byte[] innerRequestBody) {
        this.innerRequestBody = innerRequestBody;
    }

    public byte[] getEncodedPreviousRequest(){
        return encodedPreviousRequest;
    }

    public void setEncodedPreviousRequest(byte[] encodedPreviousRequest) {
        this.encodedPreviousRequest = encodedPreviousRequest;
    }

    public EncryptionType getEncryptionType() {
        return encryptionType;
    }

    public void setEncryptionType(EncryptionType type) {
        this.encryptionType = type;
    }

    public boolean isPreauthRequired() {
        return preauthRequired;
    }

    public void setPreauthRequired(boolean preauthRequired) {
        this.preauthRequired = preauthRequired;
    }
}
