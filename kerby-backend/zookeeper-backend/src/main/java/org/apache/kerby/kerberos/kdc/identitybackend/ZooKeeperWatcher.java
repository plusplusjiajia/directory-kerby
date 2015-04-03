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
import org.apache.zookeeper.WatchedEvent;
import org.apache.zookeeper.Watcher;
import org.apache.zookeeper.ZooKeeper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.login.Configuration;
import java.io.IOException;

public class ZooKeeperWatcher implements Watcher {
    private static final Logger LOG = LoggerFactory.getLogger(ZooKeeperWatcher.class);

    public ZooKeeperWatcher() {}

    /**
     * This will watch all the kdb update event so that it's timely synced.
     *
     * @param event
     */
    @Override
    public void process(WatchedEvent event) {
        System.out.println("I got an event: " + event.getType());
        if(event.getType() == Event.EventType.NodeChildrenChanged) {

        }
        LOG.debug("Received ZooKeeper Event, " +
            "type=" + event.getType() + ", " +
            "state=" + event.getState() + ", " +
            "path=" + event.getPath());

        switch (event.getType()) {

            // If event type is NONE, this is a connection status change
//            case None: {
//                connectionEvent(event);
//                break;
//            }
//
//            // Otherwise pass along to the listeners
//
//            case NodeCreated: {
//                for (ZooKeeperListener listener : listeners) {
//                    listener.nodeCreated(event.getPath());
//                }
//                break;
//            }
//
//            case NodeDeleted: {
//                for (ZooKeeperListener listener : listeners) {
//                    listener.nodeDeleted(event.getPath());
//                }
//                break;
//            }
//
//            case NodeDataChanged: {
//                for (ZooKeeperListener listener : listeners) {
//                    listener.nodeDataChanged(event.getPath());
//                }
//                break;
//            }
//
//            case NodeChildrenChanged: {
//                for (ZooKeeperListener listener : listeners) {
//                    listener.nodeChildrenChanged(event.getPath());
//                }
//                break;
//            }
        }

    }

}