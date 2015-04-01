package org.apache.kerby.kerberos.kdc.identitybackend;

import org.apache.kerby.config.Config;

import javax.security.auth.login.Configuration;
import java.io.File;

/**
 * Created by root on 3/31/15.
 */
public class ZKConfig {

    private static String zkHost;
    private static int zkPort;
    private static File dataDir;
    private static File dataLogDir;

    /**
     * Return the ZK Quorum servers string given the specified configuration.
     *
     * @param config
     * @return Quorum servers
     */
    public static String getZKQuorumServersString(Config config) {
        zkHost = config.getString(ZKConfKey.ZK_HOST);
        return zkHost;
    }

    public static int getZkPort(Config config) {
        zkPort = config.getInt(ZKConfKey.ZK_PORT);
        return zkPort;
    }

    public static File getDataDir(Config config) {
                dataDir = new File(config.getString(ZKConfKey.DATA_DIR));
        return dataDir;
    }

    public static File getDataLogDir(Config config) {
        dataLogDir = new File(config.getString(ZKConfKey.DATA_LOG_DIR));
        return dataLogDir;
    }


}