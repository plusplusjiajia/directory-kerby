package org.apache.kerby.kerberos.kerb.server.request;

import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.fast.FastOptions;
import sun.security.krb5.internal.PAData;

public class KdcRequestState {

    private EncryptionKey armorKey;
    private EncryptionKey strengthenKey;
    private PAData cookie;
    private FastOptions fastOptions;
    private int fastInternalFlags;
    private String realmData;

    public EncryptionKey getArmorKey() {
        return armorKey;
    }

    public void setArmorKey(EncryptionKey armorKey) {
        this.armorKey = armorKey;
    }

    public String getRealmData() {
        return realmData;
    }

    public void setRealmData(String realmData) {
        this.realmData = realmData;
    }
}
