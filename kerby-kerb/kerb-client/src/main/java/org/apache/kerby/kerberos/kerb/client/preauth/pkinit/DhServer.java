/*
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
package org.apache.kerby.kerberos.kerb.client.preauth.pkinit;


import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/**
 * The server-side of Diffie-Hellman key agreement for Kerberos PKINIT.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
class DhServer
{
    private static AlgorithmParameterSpec AES_IV = new IvParameterSpec( new byte[16] );

    private KeyAgreement serverKeyAgree;
    private SecretKey serverAesKey;


    byte[] initAndDoPhase( byte[] clientPubKeyEnc ) throws Exception
    {
        /*
         * The server has received the client's public key in encoded format.  The
         * server instantiates a DH public key from the encoded key material.
         */
        KeyFactory serverKeyFac = KeyFactory.getInstance( "DH" );
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec( clientPubKeyEnc );
        PublicKey clientPubKey = serverKeyFac.generatePublic( x509KeySpec );

        /*
         * The server gets the DH parameters associated with the client's public
         * key.  The server must use the same parameters when it generates its own key pair.
         */
        DHParameterSpec dhParamSpec = ( ( DHPublicKey ) clientPubKey ).getParams();

        // The server creates its own DH key pair.
        KeyPairGenerator serverKpairGen = KeyPairGenerator.getInstance( "DH" );
        serverKpairGen.initialize( dhParamSpec );
        KeyPair serverKpair = serverKpairGen.generateKeyPair();

        // The server creates and initializes its DH KeyAgreement object.
        serverKeyAgree = KeyAgreement.getInstance( "DH" );
        serverKeyAgree.init( serverKpair.getPrivate() );

        /*
         * The server uses the client's public key for the only phase of its
         * side of the DH protocol.
         */
        serverKeyAgree.doPhase( clientPubKey, true );

        // The server encodes its public key, and sends it over to the client.
        return serverKpair.getPublic().getEncoded();
    }


    byte[] generateKey( byte[] clientDhNonce, byte[] serverDhNonce )
    {
        // ZZ length will be same as public key.
        byte[] dhSharedSecret = serverKeyAgree.generateSecret();
        byte[] x = dhSharedSecret;

        if ( ( clientDhNonce != null && clientDhNonce.length > 0 )
            && ( serverDhNonce != null && serverDhNonce.length > 0 ) )
        {
            x = concatenateBytes( dhSharedSecret, clientDhNonce );
            x = concatenateBytes( x, serverDhNonce );
        }

        byte[] secret = OctetString2Key.kTruncate( dhSharedSecret.length, x );
        serverAesKey = new SecretKeySpec( secret, 0, 16, "AES" );

        return serverAesKey.getEncoded();
    }


    /**
     * Encrypt using AES in CTS mode.
     *
     * @param cleartext
     * @return The cipher text.
     * @throws Exception
     */
    byte[] encryptAes( byte[] clearText ) throws Exception
    {
        // Use the secret key to encrypt/decrypt data.
        Cipher serverCipher = Cipher.getInstance( "AES/CTS/NoPadding" );
        serverCipher.init( Cipher.ENCRYPT_MODE, serverAesKey, AES_IV );

        return serverCipher.doFinal( clearText );
    }


    byte[] concatenateBytes( byte[] array1, byte[] array2 )
    {
        byte concatenatedBytes[] = new byte[array1.length + array2.length];

        for ( int i = 0; i < array1.length; i++ )
        {
            concatenatedBytes[i] = array1[i];
        }

        for ( int j = array1.length; j < concatenatedBytes.length; j++ )
        {
            concatenatedBytes[j] = array2[j - array1.length];
        }

        return concatenatedBytes;
    }
}
