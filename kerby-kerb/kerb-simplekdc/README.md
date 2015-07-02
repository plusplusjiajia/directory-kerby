kerb-simplekdc
============

* Create principle with principal name.
<pre>
simpleKdcServer.createPrincipal(principal);
</pre>
* Add principle with principal name and password.
<pre>
simpleKdcServer.createPrincipal(principal, password);
</pre>
* Create principles with principal names.
<pre>
simpleKdcServer.createPrincipals(principals);
</pre>
* Creates principals and export their keys to the specified keytab file.
<pre>
simpleKdcServer.createAndExportPrincipals(keytabFile principals);
</pre>
* Delete principle with principal name.
<pre>
simpleKdcServer.deletePrincipal(principal);
</pre>
</pre>
* Delete principles with principal names.
<pre>
simpleKdcServer.deletePrincipals(principals);
</pre>
</pre>
* Export principles to keytab file.
<pre>
simpleKdcServer.exportPrincipals(keytabFile);
</pre>

