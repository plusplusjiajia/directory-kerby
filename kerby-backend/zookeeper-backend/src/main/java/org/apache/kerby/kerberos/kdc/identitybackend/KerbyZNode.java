package org.apache.kerby.kerberos.kdc.identitybackend;

import org.apache.kerby.kerberos.kerb.crypto.util.BytesUtil;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionType;
import org.apache.kerby.util.UTF8;
import org.apache.zookeeper.CreateMode;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.ZooKeeper;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class KerbyZNode {

    public final static String IDENTITIES_ZNODE_NAME = "identities";
    public final static String PRINCIPAL_NAME_ZNODE_NAME = "principalName";
    public final static String KEY_VERSION_ZNODE_NAME = "keyVersion";
    public final static String KDC_FLAGS_ZNODE_NAME = "kdcFlags";
    public final static String DISABLED_ZNODE_NAME = "disabled";
    public final static String LOCKED_ZNODE_NAME = "locked";
    public final static String EXPIRE_TIME_ZNODE_NAME = "expireTime";
    public final static String CREATED_TIME_ZNODE_NAME = "createdTime";
    public final static String KEYS_ZNODE_NAME = "keys";
    public final static String KEY_TYPE_ZNODE_NAME = "keyType";
    public final static String KEY_DATA_ZNODE_NAME = "keyData";
    public final static String ENCRYPTION_KEY_NO_ZNODE_NAME = "keyNo";


    private ZooKeeper zk;
    private String baseZNode = "/kerby";
    private String identitiesZNode;

    public KerbyZNode(ZooKeeper zk) throws KeeperException {
       this.zk = zk;
       this.identitiesZNode = ZKUtil.joinZNode(this.baseZNode, IDENTITIES_ZNODE_NAME);
       if (ZKUtil.checkExists(zk, this.identitiesZNode) == -1) {
           ZKUtil.createWithParents(this.zk, this.identitiesZNode);
       }
    }

    public String getIdentitiesZNode() {
        return this.identitiesZNode;
    }

    public String getIndentityZNode(String principalName) {
        return ZKUtil.joinZNode(this.identitiesZNode, principalName);
    }

    public String getPrincipalNameZnode(String principalName) {
        return ZKUtil.joinZNode(getIndentityZNode(principalName), PRINCIPAL_NAME_ZNODE_NAME);
    }

    public String getKeyVersionZNode(String principalName) {
        return ZKUtil.joinZNode(getIndentityZNode(principalName), KEY_VERSION_ZNODE_NAME);
    }

    public String getKdcFlagsZNode(String principalName) {
        return ZKUtil.joinZNode(getIndentityZNode(principalName), KDC_FLAGS_ZNODE_NAME);
    }

    public String getDisabledZNode(String principalName) {
        return ZKUtil.joinZNode(getIndentityZNode(principalName), DISABLED_ZNODE_NAME);
    }

    public String getLockedZNode(String principalName) {
        return ZKUtil.joinZNode(getIndentityZNode(principalName), LOCKED_ZNODE_NAME);
    }

    public String getExpireTimeZNode(String principalName) {
        return ZKUtil.joinZNode(getIndentityZNode(principalName), EXPIRE_TIME_ZNODE_NAME);
    }

    public String getCreatedTimeZNode(String principalName) {
        return ZKUtil.joinZNode(getIndentityZNode(principalName), CREATED_TIME_ZNODE_NAME);
    }

    public String getKeysZNode(String principalName) {
        return ZKUtil.joinZNode(getIndentityZNode(principalName), KEYS_ZNODE_NAME);
    }

    public String getKeyTypeZNode(String principalName, String type) {
        return ZKUtil.joinZNode(getKeysZNode(principalName), type);
    }

    public String getEncryptionKeyTypeZNode(String principalName, String type) {
        return ZKUtil.joinZNode(getKeyTypeZNode(principalName, type), KEY_TYPE_ZNODE_NAME);
    }

    public String getEncryptionKeyDataZNode(String principalName, String type) {
        return ZKUtil.joinZNode(getKeyTypeZNode(principalName, type), KEY_DATA_ZNODE_NAME);
    }

    public String getEncryptionKeyNoZNode(String principalName, String type) {
        return ZKUtil.joinZNode(getKeyTypeZNode(principalName, type), ENCRYPTION_KEY_NO_ZNODE_NAME);
    }

    public boolean identityExists(String principalName) throws KeeperException {
        return ZKUtil.checkExists(this.zk, getIndentityZNode(principalName)) >= 0;
    }

    public boolean encryptionTypeExists(String principalName, String type) throws KeeperException {
        return ZKUtil.checkExists(this.zk, getKeyTypeZNode(principalName, type)) >= 0;
    }

    public List<String> getIdentityNames(int start, int limit) throws KeeperException {
        List<String> identityNames = ZKUtil.listChildrenNoWatch(this.zk, getIdentitiesZNode());
        List<String> principals = new ArrayList<>(limit);
        for (int i = start - 1;  i < limit - 1; i++) {
            principals.add(identityNames.get(i));
        }
        return principals;
    }
    public String getPrincipalName(String principalName) throws KeeperException {
        if (!identityExists(principalName)) {
//            throw new IllegalArgumentException("The principal name " + principalName + " is not found");
                return null;
        }
        byte[] data = ZKUtil.getData(this.zk, getPrincipalNameZnode(principalName));
        return UTF8.toString(data);
    }

    public int getKeyVersion(String principalName) throws KeeperException {
        if (!identityExists(principalName)) {
            throw new IllegalArgumentException("The principal name " + principalName + " is not found");
        }
        byte[] data = ZKUtil.getData(this.zk, getKeyVersionZNode(principalName));
        return BytesUtil.bytes2int(data, true);
    }

    public int getKdcFlags(String principalName) throws KeeperException {
        if (!identityExists(principalName)) {
            throw new IllegalArgumentException("The principal name " + principalName + " is not found");
        }
        byte[] data = ZKUtil.getData(this.zk, getKdcFlagsZNode(principalName));
        return BytesUtil.bytes2int(data, true);
    }

    public boolean getDisabled(String principalName) throws KeeperException {
        if (!identityExists(principalName)) {
            throw new IllegalArgumentException("The principal name " + principalName + " is not found");
        }
        byte[] data = ZKUtil.getData(this.zk, getDisabledZNode(principalName));
        int disabled = BytesUtil.bytes2int(data, true);
        return disabled == 1;
    }

    public boolean getLocked(String principalName) throws KeeperException {
        if (!identityExists(principalName)) {
            throw new IllegalArgumentException("The principal name " + principalName + " is not found");
        }
        byte[] data = ZKUtil.getData(this.zk, getLockedZNode(principalName));
        int locked = BytesUtil.bytes2int(data, true);
        return locked == 1;
    }

    public KerberosTime getExpireTime(String principalName) throws KeeperException {
        if (!identityExists(principalName)) {
            throw new IllegalArgumentException("The principal name " + principalName + " is not found");
        }
        byte[] data = ZKUtil.getData(this.zk, getExpireTimeZNode(principalName));
        long time = BytesUtil.bytes2long(data, true);
        return new KerberosTime(time);
    }

    public KerberosTime getCreatedTime(String principalName) throws KeeperException {
        if (!identityExists(principalName)) {
            throw new IllegalArgumentException("The principal name " + principalName + " is not found");
        }
        byte[] data = ZKUtil.getData(this.zk, getCreatedTimeZNode(principalName));
        long time = BytesUtil.bytes2long(data, true);
        return new KerberosTime(time);
    }

    public EncryptionType getEncryptionKeyType(String principalName, String type) throws KeeperException {
        if(!encryptionTypeExists(principalName, type)) {
            throw  new IllegalArgumentException("The Encryption Type " + type + " is not found");
        }
        byte[] data = ZKUtil.getData(this.zk, getEncryptionKeyTypeZNode(principalName, type));
        return EncryptionType.fromName(UTF8.toString(data));
    }

    public byte[] getEncryptionKeyData(String principalName, String type) throws KeeperException {
        if (!encryptionTypeExists(principalName, type)) {
            throw new IllegalArgumentException("The Encryption Type " + type + " is not found");
        }
        byte[] data = ZKUtil.getData(this.zk, getEncryptionKeyDataZNode(principalName, type));
        return data;
    }

    public int getEncryptionKeyNo(String principalName, String type) throws KeeperException {
        if (!encryptionTypeExists(principalName, type)) {
            throw new IllegalArgumentException("The Encryption Type " + type + " is not found");
        }
        byte[] data = ZKUtil.getData(this.zk, getEncryptionKeyNoZNode(principalName, type));
        return BytesUtil.bytes2int(data, true);
    }

    public Map<EncryptionType, EncryptionKey> getKeysMap(String principalName) throws KeeperException {
        if (!identityExists(principalName)) {
            throw new IllegalArgumentException("The principal name " + principalName + " is not found");
        }
        Map<EncryptionType, EncryptionKey> keys = new HashMap<EncryptionType, EncryptionKey>();
        List<String> typeNames = ZKUtil.listChildrenNoWatch(this.zk, getKeysZNode(principalName));
        for(String typeName : typeNames) {
            EncryptionType type = getEncryptionKeyType(principalName, typeName);
            byte[] data = getEncryptionKeyData(principalName, typeName);
            int no = getEncryptionKeyNo(principalName, typeName);
            keys.put(type, new  EncryptionKey(type, data ,no));
        }
        return keys;
    }

    public List<EncryptionKey> getKeys(String principalName) throws KeeperException{
        if (!identityExists(principalName)) {
            throw new IllegalArgumentException("The principal name " + principalName + " is not found");
        }
        List<String> typeNames = ZKUtil.listChildrenNoWatch(this.zk, getKeysZNode(principalName));
        List<EncryptionKey> keys = new ArrayList<EncryptionKey>(typeNames.size());
        for (String typeName : typeNames) {
            EncryptionType type = getEncryptionKeyType(principalName, typeName);
            byte[] data = getEncryptionKeyData(principalName, typeName);
            int no = getEncryptionKeyNo(principalName, typeName);
            keys.add(new EncryptionKey(type, data, no));
        }
        return keys;
    }

    public void setPrincipal(String principalName) throws KeeperException, InterruptedException {
        if (ZKUtil.checkExists(this.zk, getIndentityZNode(principalName)) == -1) {
            ZKUtil.createWithParents(this.zk, getIndentityZNode(principalName));
        }
    }

    /**
     * Sets the pricipalName in zookeeper.
     *
     * @param principalName
     * @param principal
     * @throws KeeperException
     */
    public void setPrincipalName(String principalName, String principal) throws KeeperException, InterruptedException {
        ZKUtil.setData(this.zk, getPrincipalNameZnode(principalName), UTF8.toBytes(principal));
    }

    public void setKeyVersion(String principalName, int keyVersion) throws InterruptedException, KeeperException {
        ZKUtil.setData(this.zk, getKeyVersionZNode(principalName), BytesUtil.int2bytes(keyVersion, true));
    }

    public void setKdcFlags(String principalName, int kdcFlags) throws InterruptedException, KeeperException {
        ZKUtil.setData(this.zk, getKdcFlagsZNode(principalName), BytesUtil.int2bytes(kdcFlags, true));
    }

    public void setDisabled(String principalName, boolean disabled) throws InterruptedException, KeeperException {
        int value;
        if(disabled) {
            value = 1;
        } else {
            value = 0;
        }
        ZKUtil.setData(this.zk, getDisabledZNode(principalName), BytesUtil.int2bytes(value, true));
    }

    public void setLocked(String principalName, boolean locked) throws InterruptedException, KeeperException {
        int value;
        if(locked) {
            value = 1;
        } else {
            value = 0;
        }
        ZKUtil.setData(this.zk, getLockedZNode(principalName), BytesUtil.int2bytes(value, true));
    }

    public void setExpireTime(String principalName, KerberosTime time)throws InterruptedException, KeeperException {
        ZKUtil.setData(this.zk, getExpireTimeZNode(principalName), BytesUtil.long2bytes(time.getTime(), true));
    }

    public void setCreatedTime(String principalName, KerberosTime time) throws InterruptedException, KeeperException {
        ZKUtil.setData(this.zk, getCreatedTimeZNode(principalName), BytesUtil.long2bytes(time.getTime(), true));
    }

    public void setKeys(String principalName, Map<EncryptionType, EncryptionKey> keys) throws InterruptedException, KeeperException {
        if (ZKUtil.checkExists(this.zk, getKeysZNode(principalName)) == -1) {
            ZKUtil.createWithParents(this.zk, getKeysZNode(principalName));
        }
        Iterator it = keys.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry pair = (Map.Entry) it.next();
            EncryptionType key = (EncryptionType) pair.getKey();
            ZKUtil.createWithParents(this.zk, getKeyTypeZNode(principalName, key.getName()));
            EncryptionKey value = (EncryptionKey) pair.getValue();
            ZKUtil.setData(this.zk, getEncryptionKeyTypeZNode(principalName, key.getName()), UTF8.toBytes(value.getKeyType().getName()));
            ZKUtil.setData(this.zk, getEncryptionKeyDataZNode(principalName, key.getName()), value.getKeyData());
            ZKUtil.setData(this.zk, getEncryptionKeyNoZNode(principalName, key.getName()), BytesUtil.int2bytes(value.getKvno(), true));
        }
    }

    public void deleteIdentity(String principalName) throws KeeperException, InterruptedException {
        ZKUtil.deleteNodeRecursively(this.zk, getIndentityZNode(principalName));
    }

    public void createSetData(String path, byte[] data, CreateMode createMode) throws KeeperException, InterruptedException {
//        if (checkExists(path) == -1) {
//            zk.create(path, data, acl, createMode);
//        } else {
            zk.setData(path, data, 1);
//        }
    }

//    private int checkExists(String path) throws KeeperException, InterruptedException {
//        Stat s = zk.exists(path, false);
//        return s !=null ? s.getAversion() : -1;
//    }

}
