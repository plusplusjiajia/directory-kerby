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
package org.apache.kerby.kerberos.provider.token;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.apache.kerby.kerberos.kerb.provider.TokenDecoder;
import org.apache.kerby.kerberos.kerb.spec.base.AuthToken;

import java.io.IOException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

/**
 * JWT token decoder, implemented using Nimbus JWT library.
 */
public class JwtTokenDecoder implements TokenDecoder {
    private RSAPrivateKey decryptionKey;
    private RSAPublicKey verifyKey;

    @Override
    public AuthToken decodeFromBytes(byte[] content) throws IOException {
        String tokenStr = String.valueOf(content);

        return decodeFromString(tokenStr);
    }

    @Override
    public AuthToken decodeFromString(String content) throws IOException {
       JWT jwt = null;
        try {
            jwt = JWTParser.parse(content);
        } catch (ParseException e) {
            // Invalid JWT encoding
            throw new IOException("Failed to parse JWT token string", e);
        }
        // Check the JWT type
        if (jwt instanceof PlainJWT) {
            PlainJWT plainObject = (PlainJWT) jwt;
            try {
                return new JwtAuthToken(plainObject.getJWTClaimsSet());
            } catch (ParseException e) {
                throw new IOException("Failed to get JWT claims set", e);
            }
        } else if (jwt instanceof EncryptedJWT) {
            EncryptedJWT encryptedJWT = (EncryptedJWT) jwt;
            decryptEncryptedJWT(encryptedJWT);
            SignedJWT signedJWT = encryptedJWT.getPayload().toSignedJWT();
            if (signedJWT != null) {
                boolean success = verifySignedJWT(signedJWT);
                if (success) {
                    try {
                        return new JwtAuthToken(signedJWT.getJWTClaimsSet());
                    } catch (ParseException e) {
                        throw new IOException("Failed to get JWT claims set", e);
                    }
                } else {
                    return null;
                }
            } else {
                try {
                    return new JwtAuthToken(encryptedJWT.getJWTClaimsSet());
                } catch (ParseException e) {
                    throw new IOException("Failed to get JWT claims set", e);
                }
            }
        } else if (jwt instanceof SignedJWT) {
            SignedJWT signedJWT = (SignedJWT) jwt;
            boolean success = verifySignedJWT(signedJWT);
            if (success) {
                try {
                    return new JwtAuthToken(signedJWT.getJWTClaimsSet());
                } catch (ParseException e) {
                    throw new IOException("Failed to get JWT claims set", e);
                }
            } else {
                return null;
            }
        } else {
            throw new IOException("Unexpected JWT type: " + jwt);
        }
    }

    /**
     * Decrypt the Encrypted JWT
     *
     * @param encryptedJWT
     */
    public void decryptEncryptedJWT(EncryptedJWT encryptedJWT) throws IOException {
        RSADecrypter decrypter = new RSADecrypter(decryptionKey);
        try {
            encryptedJWT.decrypt(decrypter);
        } catch (JOSEException e) {
            throw new IOException("Failed to decrypt the encrypted JWT", e);
        }
    }

    /**
     * Set the decryption key
     *
     * @param key a private key
     */
    public void setDecryptionKey(RSAPrivateKey key) {
        decryptionKey = key;
    }

    /**
     * verify the Signed JWT
     *
     * @param signedJWT
     * @return whether verify success
     */
    public boolean verifySignedJWT(SignedJWT signedJWT) throws IOException {
        JWSVerifier verifier = new RSASSAVerifier(verifyKey);
        try {
            return signedJWT.verify(verifier);
        } catch (JOSEException e) {
            throw new IOException("Failed to verify the signed JWT", e);
        }
    }

    /**
     * set the verify key
     *
     * @param key a public key
     */
    public void setVerifyKey(RSAPublicKey key) {
        verifyKey = key;
    }

}
