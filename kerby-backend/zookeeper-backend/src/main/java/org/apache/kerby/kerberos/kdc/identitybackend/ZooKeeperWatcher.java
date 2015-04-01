package org.apache.kerby.kerberos.kdc.identitybackend;

import org.apache.kerby.config.Config;
import org.apache.zookeeper.WatchedEvent;
import org.apache.zookeeper.Watcher;
import org.apache.zookeeper.ZooKeeper;

import javax.security.auth.login.Configuration;
import java.io.IOException;

public class ZooKeeperWatcher implements Watcher {

    private ZooKeeper zk;
    public Config config;
    private String quorum;
    private int port;

    int timeout = 100;

    public ZooKeeperWatcher(Config config) {
        this.config = config;
        this.quorum = ZKConfig.getZKQuorumServersString(config);
        this.port = ZKConfig.getZkPort(config);
        try {
            this.zk = new ZooKeeper(this.quorum, this.port, null);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public ZooKeeper getZooKeeper() {
        return this.zk;
    }

    public  static final ZooKeeperWatcher instance = new ZooKeeperWatcher();
    private ZooKeeperWatcher() {}
    public void process(WatchedEvent event) {}
}