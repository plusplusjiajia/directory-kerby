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
package org.apache.kerby.kerberos.tool.kdcinit;

import org.apache.kerby.KOption;
import org.apache.kerby.KOptionType;

public enum KdcInitOption implements KOption {
    NONE("NONE"),
    CONF_DIR("-c", "conf dir", KOptionType.DIR),
    KEYTAB("-keytab", "keytab file", KOptionType.FILE),
    MASTER_KEY_TYPE("-k", "master key type", KOptionType.STR),
    STASH_FILE_NAME("-sf", "stash file name", KOptionType.FILE),
    PASSWORD("-p", "password", KOptionType.STR);

    private String name;
    private KOptionType type = KOptionType.NONE;
    private String description;
    private Object value;

    KdcInitOption(String description) {
        this(description, KOptionType.NOV); // As a flag by default
    }

    KdcInitOption(String description, KOptionType type) {
        this.description = description;
        this.type = type;
    }

    KdcInitOption(String name, String description) {
        this(name, description, KOptionType.NOV); // As a flag by default
    }

    KdcInitOption(String name, String description, KOptionType type) {
        this.name = name;
        this.description = description;
        this.type = type;
    }

    @Override
    public String getOptionName() {
        return name();
    }

    @Override
    public void setType(KOptionType type) {
        this.type = type;
    }

    @Override
    public KOptionType getType() {
        return this.type;
    }

    @Override
    public void setName(String name) {
        this.name = name;
    }

    @Override
    public void setDescription(String description) {
        this.description = description;
    }

    @Override
    public String getName() {
        if (name != null) {
            return name;
        }
        return name();
    }

    @Override
    public String getDescription() {
        return this.description;
    }

    @Override
    public void setValue(Object value) {
        this.value = value;
    }

    @Override
    public Object getValue() {
        return value;
    }

    public static KdcInitOption fromName(String name) {
        if (name != null) {
            for (KdcInitOption ko : values()) {
                if (ko.getName().equals(name)) {
                    return (KdcInitOption) ko;
                }
            }
        }
        return NONE;
    }
}
