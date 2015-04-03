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
package org.apache.kerby.kerberos.kdc.identitybackend;

import org.apache.kerby.config.Config;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.identity.backend.AbstractIdentityBackend;
import org.apache.kerby.kerberos.kerb.spec.base.PrincipalName;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.WatchedEvent;
import org.apache.zookeeper.Watcher;
import org.apache.zookeeper.ZooKeeper;
import org.apache.zookeeper.server.ServerConfig;
import org.apache.zookeeper.server.ZooKeeperServerMain;
import org.apache.zookeeper.server.quorum.QuorumPeerConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Properties;

/**
 * A Zookeeper based backend implementation. Currently it uses an embedded
 * Zookeeper. In follow up it will be enhanced to support standalone Zookeeper
 * cluster for replication and reliability.
 */
public class ZookeeperIdentityBackend extends AbstractIdentityBackend {
    private static final Logger LOG = LoggerFactory.getLogger(ZookeeperIdentityBackend.class);
    private Config config;
    private String zkHost;
    private int zkPort;
    private File dataDir;
    private File dataLogDir;
    private ZooKeeper zooKeeper;
    private ZooKeeperWatcher zkw;
    private KerbyZNode kerbyZNode;

    /**
     * Constructing an instance using specified config that contains anything
     * to be used to init the Zookeeper backend.
     *
     * @param config
     */
    public ZookeeperIdentityBackend(Config config) {
        this.config = config;
        init();
    }

    public ZooKeeper getZooKeeper() {
        return zooKeeper;
    }

    private void init() {
        zkHost = config.getString(ZKConfKey.ZK_HOST);
        zkPort = config.getInt(ZKConfKey.ZK_PORT);
        dataDir = new File(config.getString(ZKConfKey.DATA_DIR));
        dataLogDir = new File(config.getString(ZKConfKey.DATA_LOG_DIR));

        startEmbeddedZookeeper();
        connectZK();
        try {
            kerbyZNode = new KerbyZNode(zooKeeper);
        } catch (KeeperException e) {
            e.printStackTrace();
        }
    }

    /**
     * Prepare connection to Zookeeper server.
     */
    private void connectZK() {
        try {
            zkw = new ZooKeeperWatcher();
            zooKeeper = new ZooKeeper(zkHost, zkPort, zkw);
        } catch (IOException e) {
            throw new RuntimeException("Failed to prepare Zookeeper connection");
        }
    }

    /**
     * Load identities from file
     */
    public void load() throws IOException {
        // TODO: prepare zookeeper connection to the server.
//        ZooKeeper zooKeeper = null;

        // TODO: load the kdb file from zookeeper
        connectZK();
    }

    private void startEmbeddedZookeeper() {

        Properties startupProperties = new Properties();
        startupProperties.put("dataDir", dataDir.getAbsolutePath());
        startupProperties.put("dataLogDir", dataLogDir.getAbsolutePath());
        startupProperties.put("clientPort", zkPort);

        QuorumPeerConfig quorumConfiguration = new QuorumPeerConfig();
        try {
            quorumConfiguration.parseProperties(startupProperties);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        final ZooKeeperServerMain zooKeeperServer = new ZooKeeperServerMain();
        final ServerConfig configuration = new ServerConfig();
        configuration.readFrom(quorumConfiguration);

        new Thread() {
            public void run() {
                try {
                    zooKeeperServer.runFromConfig(configuration);
                } catch (IOException e) {
                    e.printStackTrace();
                    //log.error("ZooKeeper Failed", e);
                }
            }
        }.start();

    }

    @Override
    protected KrbIdentity doGetIdentity(String principalName) {
        KrbIdentity krb = new KrbIdentity(principalName);
        try {
            if (kerbyZNode.getPrincipalName(principalName) == null) {
                return null;
            }
            krb.setPrincipal(new PrincipalName(kerbyZNode.getPrincipalName(principalName)));
            krb.setCreatedTime(kerbyZNode.getCreatedTime(principalName));
            krb.setDisabled(kerbyZNode.getDisabled(principalName));
            krb.setExpireTime(kerbyZNode.getExpireTime(principalName));
            krb.setKdcFlags(kerbyZNode.getKdcFlags(principalName));
            krb.addKeys(kerbyZNode.getKeys(principalName));
            krb.setKeyVersion(kerbyZNode.getKeyVersion(principalName));
            krb.setLocked(kerbyZNode.getLocked(principalName));
        } catch (KeeperException e) {
            LOG.error("Fail to get identity from zookeeper", e);
        }
        return krb;
    }

    @Override
    protected KrbIdentity doAddIdentity(KrbIdentity identity) {
        try {
            setIdentity(identity);
        } catch (KeeperException e) {
            LOG.error("Fail to add identity in zookeeper", e);
        }
        return identity;
    }

    @Override
    protected KrbIdentity doUpdateIdentity(KrbIdentity identity) {
        try {
            setIdentity(identity);
        } catch (KeeperException e) {
            LOG.error("Fail to update identity in zookeeper", e);
        }
        return identity;
    }

    @Override
    protected void doDeleteIdentity(String principalName) {
        try {
            kerbyZNode.deleteIdentity(principalName);
        } catch (KeeperException e) {
            LOG.error("Fail to delete identity in zookeeper", e);
        }
    }

    @Override
    public List<String> getIdentities(int start, int limit) {
        List<String> identityNames = null;
        try {
            identityNames = kerbyZNode.getIdentityNames();
        } catch (KeeperException e) {
            LOG.error("Fail to get identities from zookeeper", e);
        }
        return identityNames;
    }

    private void setIdentity(KrbIdentity identity) throws KeeperException {
        kerbyZNode.setPrincipal(identity.getPrincipalName());
        kerbyZNode.setPrincipalName(identity.getPrincipalName(), identity.getPrincipalName());
        kerbyZNode.setCreatedTime(identity.getPrincipalName(), identity.getCreatedTime());
        kerbyZNode.setDisabled(identity.getPrincipalName(), identity.isDisabled());
        kerbyZNode.setExpireTime(identity.getPrincipalName(), identity.getExpireTime());
        kerbyZNode.setKdcFlags(identity.getPrincipalName(), identity.getKdcFlags());
        kerbyZNode.setKeys(identity.getPrincipalName(), identity.getKeys());
        kerbyZNode.setKeyVersion(identity.getPrincipalName(), identity.getKeyVersion());
        kerbyZNode.setLocked(identity.getPrincipalName(), identity.isLocked());
    }
}
