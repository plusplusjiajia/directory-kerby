package org.haox.kerb.client;

import org.haox.kerb.crypto.Nonce;
import org.haox.kerb.spec.type.common.PrincipalName;

public class KrbContext {
    private PrincipalName clientPrincipal;
    private String password;
    private PrincipalName serverPrincipal;
    private String kdcRealm;

    private KrbConfig config;

    public KrbContext() {

    }

    public void setKdcRealm(String realm) {
        this.kdcRealm = realm;
    }

    public String getKdcRealm() {
        if (kdcRealm != null) {
            return kdcRealm;
        }

        return config.getKdcRealm();
    }

    public int generateNonce() {
        return Nonce.value();
    }

    public long getTicketValidTime() {
        return 8 * 60 * 60 * 1000;
    }

    public PrincipalName getClientPrincipal() {
        return clientPrincipal;
    }

    public void setClientPrincipal(PrincipalName clientPrincipal) {
        this.clientPrincipal = clientPrincipal;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public PrincipalName getServerPrincipal() {
        return serverPrincipal;
    }

    public void setServerPrincipal(PrincipalName serverPrincipal) {
        this.serverPrincipal = serverPrincipal;
    }

    public KrbConfig getConfig() {
        return config;
    }

    public void setConfig(KrbConfig config) {
        this.config = config;
    }
}
