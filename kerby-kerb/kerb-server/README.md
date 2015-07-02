kerb-server
============

* Initiate a kerby kdc server with prepared confDir.
<pre>
KerbyKdcServer server = new KerbyKdcServer(confDir);
</pre>
* Set runtime folder.
<pre>
server.setWorkDir(workDir);
</pre>
* Start kerby kdc server.
<pre>
server.start();
</pre>
* Set KDC realm for ticket request
<pre>
server.setKdcRealm(realm);
</pre>
* Set KDC host.
<pre>
server.setKdcHost(kdcHost);
</pre>
* Set KDC tcp port.
<pre>
server.setKdcTcpPort(kdcTcpPort);
</pre>
* Set KDC udp port. Only makes sense when allowUdp is set.
<pre>
server.setKdcUdpPort(kdcUdpPort);
</pre>
* Set to allow TCP or not.
<pre>
server.setAllowTcp(allowTcp);
</pre>
* Set to allow UDP or not.
<pre>
server.setAllowUdp(allowUdp);
</pre>
* Allow to debug so have more logs.
<pre>
server.enableDebug();
</pre>
* Allow to hook customized kdc implementation.
<pre>
server.setInnerKdcImpl(innerKdcImpl);
</pre>

