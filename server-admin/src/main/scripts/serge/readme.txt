(9/1/2023 by Jeff Gaynor)

There are two scripts that will update the clients on this system.
It has to be done in two separate stages, about a minute a part so that
Tomcat has a chance to notice the changes and update, otherwise the edit
to the web.xml files that points to the correct configuration might get
overwritten.

Requirements
---
* Download the version of cilogon-oa2-client.war to ~/downloads.
* Download the OA4MP oauth2.war to ~/downloads
* Run the following as root:

1. cil-update.sh - copy the war, renaming the war as needed
 --> wait at least minute by the clock <--

2. cil-config.sh -- this uses sed to change the configuration name
                    it will also restart tomcat.

At the end of this, you should have everything updated and running.
Remember that restarting Tomcat can be slow, so give it a few minutes before
testing.

Note that this is set to my home directories (/home/jgaynor) and if you want
to move things, just change the SOURCE_DIR in the scripts.
