This directory contains the install scripts for setting up the Docker image of
a Pelican server. The aim is to create an administrative client which manages
a service client. Pelican can function as  the authorization layer and simply
use RFC 7523 requests via the service client so that OA4MP is simply a dedicated
issuer.


It will create an admin client and regular client. The regular client uses RFC 7523
with keys and this allows Pelican to use OA4MP as a dedicated issuer while it handles authorization.

This requires an ini file that contains the path to the system configuration and the name there.
It also requires the names of the admin and service client. You install OA4MP with the
-preprocess flag to point to the pelican ini file which then has all of the placeholders
for the new OA4MP install updated. At the end of running server-installer.jar, the
Pelican script can be just run without any actual intervention.



Requirements
------------

* An OA4MP installer
* An OA4MP with QDL extensions install, configured to run files from the command line.
  So your path should include $QDL_HOME/bin
* Be sure the server configuration is ready (so generate the keys for it in particular).

Use
---
Copy the Pelican directory someplace. This has templates that should be resolved by the installer,
so during OA4MP install, specify the -preprocess flag and point it to pelican-cfg.ini,

E.g.

Set your $OA4MP_SERVER directory then run the installer. ($> is the bash prompt)

$> export OA4MP_SERVER=/opt/oa4mp-server
$> java -jar server-installer.jar install -dir $OA4MP_SERVER -preprocess /path/to/pelican-cfg.ini

(Make sure you use the correct -version argument as well, if needed.)

Before starting the server for the first time, cd to the directory that has pelican-setup.qdl,
then issue

./pelican-setup.qdl pelican-cfg.ini

When this finishes successfully:
* The admin client and the service client have been created
* The public/private key pairs for each of these has been saved in
  admin_key.jwk and client_key.jwk resp. You will need these to communicate
  with the server using RFC 7523
* OA4MP should be ready for use.

Note that all communication with the server, such as token requests, new clients &c., &c.,
can be done via the client management or other web interfaces.