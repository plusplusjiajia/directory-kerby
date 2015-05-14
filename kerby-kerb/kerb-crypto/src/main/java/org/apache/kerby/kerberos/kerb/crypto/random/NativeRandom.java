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
package org.apache.kerby.kerberos.kerb.crypto.random;

import java.io.*;

/**
 * use "/dev/urandom", which is on linux, to implement RandomProvider, so it should be used on linux.
 */
public class NativeRandom implements RandomProvider {
    private InputStream input;
    private String randFile = "/dev/urandom";

    @Override
    public void init() {
        try {
            input = new FileInputStream(randFile);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void setSeed(byte[] seed) {
        try {
            OutputStream output = new FileOutputStream(randFile);
            output.write(seed);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void nextBytes(byte[] bytes) {
        try {
            input.read(bytes);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void destroy() {
        try {
            input.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
