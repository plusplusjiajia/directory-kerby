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
package org.apache.kerby.kerberos.kerb.transport;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.HashMap;
import java.util.Map;

/**
 * A combined and mixed network server handling UDP and TCP.
 */
@SuppressWarnings("PMD")
public abstract class KdcNetwork {
    private InetSocketAddress tcpAddress;
    private InetSocketAddress udpAddress;
    private boolean isStopped;
    protected final static int MAX_MESSAGE_SIZE = 65507;
    private ServerSocket tcpServer;
    private DatagramChannel udpServer;
    private Map<InetSocketAddress, KdcUdpTransport> transports =
            new HashMap<InetSocketAddress, KdcUdpTransport>();
    private ByteBuffer recvBuffer;
    public void init() {
        isStopped = false;
    }

    public void listen(InetSocketAddress tcpAddress,
                          InetSocketAddress udpAddress) throws IOException {
        this.tcpAddress = tcpAddress;
        this.udpAddress = udpAddress;

        tcpServer = new ServerSocket();
        tcpServer.setSoTimeout(100);
        tcpServer.bind(tcpAddress);

        if (udpAddress != null) {
            udpServer = DatagramChannel.open();
            udpServer.configureBlocking(false);
            udpServer.bind(udpAddress);
            recvBuffer = ByteBuffer.allocate(MAX_MESSAGE_SIZE);
        }
    }

    public void start() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                KdcNetwork.this.run();
            }
        }).start();
    }

    private void run() {
        while (true) {
            synchronized (this) {
                if (isStopped) {
                    break;
                }
            }

            if (this.tcpAddress != null) {
                try {
                    checkAndAccept();
                } catch (SocketTimeoutException e) { //NOPMD
                    //NOOP as normal
                } catch (IOException e) {
                    throw new RuntimeException("Error occured while checking tcp connections", e);
                }
            }

            if (this.udpAddress != null) {
                try {
                    checkUdpMessage();
                } catch (SocketTimeoutException e) { //NOPMD
                    //NOOP as normal
                } catch (IOException e) {
                    throw new RuntimeException("Error occured while checking udp connections", e);
                }
            }
        }
    }

    public synchronized void stop() {
        isStopped = true;
    }

    private void checkAndAccept() throws IOException {
        Socket socket;
        if ((socket = tcpServer.accept()) != null) {
            socket.setSoTimeout(3000); //TODO: from config
            KrbTransport transport = new KrbTcpTransport(socket);
            onNewTransport(transport);
        }
    }


    private void checkUdpMessage() throws IOException {
        InetSocketAddress fromAddress = (InetSocketAddress) udpServer.receive(recvBuffer);
        if (fromAddress != null) {
            recvBuffer.flip();
            KdcUdpTransport transport = transports.get(fromAddress);
            if (transport == null) {
                transport = new KdcUdpTransport(udpServer, fromAddress);
                transport.onRecvMessage(recvBuffer);
                onNewTransport(transport);
            } else {
                transport.onRecvMessage(recvBuffer);
            }
            recvBuffer = ByteBuffer.allocate(MAX_MESSAGE_SIZE);
        }
    }

    protected abstract void onNewTransport(KrbTransport transport);
}