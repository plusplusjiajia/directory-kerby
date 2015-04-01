package org.apache.kerby.kerberos.kdc.identitybackend;

import org.apache.zookeeper.CreateMode;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.Op;
import org.apache.zookeeper.ZooDefs;
import org.apache.zookeeper.ZooKeeper;
import org.apache.zookeeper.data.ACL;
import org.apache.zookeeper.data.Id;
import org.apache.zookeeper.data.Stat;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by root on 3/31/15.
 */
public class ZKUtil {

    public static final char ZNODE_PATH_SEPARATOR = '/';

    public static String joinZNode(String prefix, String suffix) {
        return prefix + ZNODE_PATH_SEPARATOR + suffix;
    }

    /**
     * Check if the specified node exists.  Sets no watches.
     *
     * @param zk  zk reference
     * @param znode path of node to watch
     * @return version of the node if it exists, -1 if does not exist
     * @throws KeeperException if unexpected zookeeper exception
     */
    public static int checkExists(ZooKeeper zk, String znode)
        throws KeeperException {
        try {
            Stat s = zk.exists(znode, null);
            return s != null ? s.getVersion() : -1;
        } catch (KeeperException e) {
            return -1;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return -1;
        }
    }

    public static byte[] getData(ZooKeeper zk, String znode)
        throws KeeperException {
        try {
            byte[] data = zk.getData(znode, false, null);
            return data;
        } catch (KeeperException.NoNodeException e) {
            return null;
        } catch (KeeperException e) {
            return null;
        } catch (InterruptedException e) {
            return null;
        }
    }

    public static List<String> listChildrenNoWatch(ZooKeeper zk, String znode)
        throws KeeperException {
        List<String> children = null;
        try {
            // List the children without watching
            children = zk.getChildren(znode, null);
        } catch (KeeperException.NoNodeException nne) {
            return null;
        } catch (InterruptedException ie) {

        }
        return children;
    }

    public static void setData(ZooKeeper zk, String znode, byte[] data)
        throws KeeperException, InterruptedException {
        if(checkExists(zk, znode) == -1) {
            createWithParents(zk, znode, data);
        } else {
            zk.setData(znode, data, -1);
        }
    }

    public static void createWithParents(ZooKeeper zk, String znode)
        throws KeeperException {
        createWithParents(zk, znode, new byte[0]);
    }

    public static void createWithParents(ZooKeeper zk, String znode, byte[] data)
        throws KeeperException {
        try {
            if (znode == null) {
                return;
            }
            zk.create(znode, data, createACL(zk, znode),
                CreateMode.PERSISTENT);
        } catch (KeeperException.NodeExistsException nee) {
            return;
        } catch (KeeperException.NoNodeException nne) {
            createWithParents(zk, getParent(znode));
            createWithParents(zk, znode, data);
        } catch (InterruptedException ie) {

        }
    }

    private static ArrayList<ACL> createACL(ZooKeeper zk, String node) {
        return ZooDefs.Ids.OPEN_ACL_UNSAFE;
    }

      /**
   * Returns the full path of the immediate parent of the specified node.
   * @param node path to get parent of
   * @return parent of path, null if passed the root node or an invalid node
   */
  public static String getParent(String node) {
    int idx = node.lastIndexOf(ZNODE_PATH_SEPARATOR);
    return idx <= 0 ? null : node.substring(0, idx);
  }

    public static void deleteNodeRecursively(ZooKeeper zk, String node) throws KeeperException {
        List<String> children = ZKUtil.listChildrenNoWatch(zk, node);
        if (children == null) return;
        if (!children.isEmpty()) {
            for (String child : children) {
                deleteNodeRecursively(zk, joinZNode(node, child));
            }
        }
        try {
            zk.delete(node, -1);
        } catch (InterruptedException e) {

        }
    }

}
