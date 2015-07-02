kerb-admin
============

* Initiate a Kadmin with confDir.
<pre>
Kadmin kadmin = new Kadmin(confDir);
</pre>
* Initiate a Kadmin with kdcSetting and backend.
<pre>
Kadmin kadmin = new Kadmin(kdcSetting, backend);
</pre>
* Add principle with principal name.
<pre>
kadmin.addPrincipal(principal);
</pre>
* Add principle with principal name and password.
<pre>
kadmin.addPrincipal(principal, password);
</pre>
* Add principle with principal name and kOptions.
<pre>
kadmin.addPrincipal(principal, kOptions);
</pre>
* Add principle with principal name, password and kOptions.
<pre>
kadmin.addPrincipal(principal, password kOptions);
</pre>
* Delete principle with principal name.
<pre>
kadmin.deletePrincipal(principal);
</pre>
* Modify principle with principal name and kOptions.
<pre>
kadmin.modifyPrincipal(principal, kOptions);
</pre>
* Rename principle.
<pre>
kadmin.renamePrincipal(oldPrincipalName, newPrincipalName);
</pre>
* Get principle with principal name.
<pre>
kadmin.getPrincipal(principalName);
</pre>
* Get all the principles.
<pre>
kadmin.getPrincipals();
</pre>
* Update password with principal name and new password.
<pre>
kadmin.updatePassword(principal, newPassword);
</pre>
* Export all identity keys to the specified keytab file.
<pre>
kadmin.exportKeyTab(keyTabFile);
</pre>





