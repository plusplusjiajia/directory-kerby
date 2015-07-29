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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import org.apache.kerby.config.Config;
import org.apache.kerby.kerberos.kdc.identitybackend.typeAdapter.EncryptionKeyAdapter;
import org.apache.kerby.kerberos.kdc.identitybackend.typeAdapter.KerberosTimeAdapter;
import org.apache.kerby.kerberos.kdc.identitybackend.typeAdapter.PrincipalNameAdapter;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.identity.backend.AbstractIdentityBackend;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.base.PrincipalName;
import org.apache.kerby.util.IOUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A Json file based backend implementation.
 *
 */
public class JsonIdentityBackend extends AbstractIdentityBackend {
    public static final String JSON_IDENTITY_BACKEND_DIR = "backend.json.dir";
    private File jsonKdbFile;
    private Gson gson;
    private static final Logger LOG = LoggerFactory.getLogger(JsonIdentityBackend.class);


    // Identities loaded from file
    private Map<String, KrbIdentity> ids;
    private long kdbFileTimeStamp;

    public JsonIdentityBackend() {

    }

    /**
     * Constructing an instance using specified config that contains anything
     * to be used to initialize the json format database.
     * @param config
     */
    public JsonIdentityBackend(Config config) {
        setConfig(config);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void doInitialize() throws KrbException {
        LOG.info("Initializing the Json identity backend.");
        createGson();
        load();
    }

    /**
     * Load identities from file
     */
    private void load() throws KrbException {
        LOG.info("Loading the identities from json file.");
        String jsonFile = getConfig().getString(JSON_IDENTITY_BACKEND_DIR);
        File jsonFileDir;
        if (jsonFile == null || jsonFile.isEmpty()) {
            jsonFileDir = getBackendConfig().getConfDir();
        } else {
            jsonFileDir = new File(jsonFile);
            if (!jsonFileDir.exists() && !jsonFileDir.mkdirs()) {
                throw new KrbException("could not create json file dir " + jsonFileDir);
            }
        }

        jsonKdbFile = new File(jsonFileDir, "json_identity_backend_file");

        if (!jsonKdbFile.exists()) {
            try {
                jsonKdbFile.createNewFile();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        checkAndLoad();
    }

    /**
     * Check kdb file timestamp to see if it's changed or not. If
     * necessary load the kdb again.
     */
    private void checkAndLoad() {
        long nowTimeStamp = jsonKdbFile.lastModified();

        if (kdbFileTimeStamp == 0 || nowTimeStamp != kdbFileTimeStamp) {
            //load ids
            String existsFileJson = null;
            try {
                existsFileJson = IOUtil.readFile(jsonKdbFile);
            } catch (IOException e) {
                throw new RuntimeException("Failed to read file", e);
            }

            ids = gson.fromJson(existsFileJson,
                new TypeToken<LinkedHashMap<String, KrbIdentity>>() {
                }.getType());
        }

        if (ids == null) {
            ids = new LinkedHashMap<>();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected KrbIdentity doGetIdentity(String principalName) {
        checkAndLoad();
        return ids.get(principalName);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected KrbIdentity doAddIdentity(KrbIdentity identity) {
        checkAndLoad();

        String principalName = identity.getPrincipalName();
        if (ids.containsKey(principalName)) {
            LOG.error("Error occurred while adding identity, principal " + principalName + " already exists.");
            throw new RuntimeException("Principal already exists.");
        }

        ids.put(identity.getPrincipalName(), identity);
        idsToFile(ids);

        return doGetIdentity(identity.getPrincipalName());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected KrbIdentity doUpdateIdentity(KrbIdentity identity) {
        checkAndLoad();
        String principalName = identity.getPrincipalName();
        if (ids.containsKey(principalName)) {
            ids.put(principalName, identity);
        } else {
            LOG.error("Error occurred while updating identity, principal " + principalName + " does not exists.");
            throw new RuntimeException("Principal does not exist.");
        }
        idsToFile(ids);
        return doGetIdentity(identity.getPrincipalName());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void doDeleteIdentity(String principalName) {
        checkAndLoad();
        if (ids.containsKey(principalName)) {
            ids.remove(principalName);
        } else {
            LOG.error("Error occurred while deleting identity, principal " + principalName + " does not exists.");
            throw new RuntimeException("Principal does not exist.");
        }
        idsToFile(ids);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected Iterable<String> doGetIdentities() throws KrbException {
        List<String> principals = new ArrayList<>(ids.keySet());
        Collections.sort(principals);

        return principals;
    }

    /**
     *Create a gson
     */
    private void createGson() {
        GsonBuilder gsonBuilder = new GsonBuilder();
        gsonBuilder.registerTypeAdapter(EncryptionKey.class, new EncryptionKeyAdapter());
        gsonBuilder.registerTypeAdapter(PrincipalName.class, new PrincipalNameAdapter());
        gsonBuilder.registerTypeAdapter(KerberosTime.class, new KerberosTimeAdapter());
        gsonBuilder.enableComplexMapKeySerialization();
        gsonBuilder.setPrettyPrinting();
        gson = gsonBuilder.create();
    }

    /**
     * Write ids into a file
     * @param ids the ids to write into the json file
     */
    private void idsToFile(Map<String, KrbIdentity> ids) {
        String newFileJson = gson.toJson(ids);
        try {
            IOUtil.writeFile(newFileJson, jsonKdbFile);
        } catch (IOException e) {
            LOG.error("Error occurred while writing ids to file: " + jsonKdbFile);
            throw new RuntimeException("Failed to write file", e);
        }
    }
}
