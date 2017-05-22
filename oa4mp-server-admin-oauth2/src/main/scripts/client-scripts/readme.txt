Client scripts for the client management API.

Introduction.
-------------
This directory contains a full set of scripts to exercise the client management API from the command line.

Requirements.
-------------
These scripts run under linux. In particular, they require some form of bash, sed and cUrl. There are no plans
to port these to any other platform at this time.

The way these scripts work is that there is a driver script, c-run.sh, that will accept a script containing json.
Various bits of information (detailed below) are replaced in the script from environment variables. The command is
run and the raw json is printed to the console. This is preferrable since there are many things that may be done
with the output and we do not want to pre-digest it into something unusable.

Also, there are two working files in the invocation directory:

input.json
output.json

The first will contain the supplied json with all the environment variables replaced. This is what is actually
submitted to the server.

The output.json file contains that response (also printed to the console).

Environment Variables.
----------------------
Note that all of these are upper case (bash's environment variables are case sensitive and some of the json keys
are the same, just lower case).

+---------------+----------------------------+-------------------------------------------------------------------+
| Name          | Value                      | Comment                                                           |
+---------------+----------------------------+-------------------------------------------------------------------+
| ADMIN_ID      | Identifier of admin client |  Created at registration                                          |
+---------------+----------------------------+-------------------------------------------------------------------+
| ADMIN_SECRET  | Secret of admin client     |        "                                                          |
+---------------+----------------------------+-------------------------------------------------------------------+
| CLIENT_ID     | Identifier of the client   |        "                                                          |
+---------------+----------------------------+-------------------------------------------------------------------+
| CLIENT_SECRET | Secret of the client       |        "                                                          |
+---------------+----------------------------+-------------------------------------------------------------------+
| SERVER        | Address of the server      | The default will be https://localhost/oauth2/clients              |
+---------------+----------------------------+-------------------------------------------------------------------+

Naming of the scripts.
----------------------
This looks more complex than it is. I decided that a very functional, predictable approach was needed. The
general format is

subject-method-type-object.json

E.g admin-set-attribute-client.json would be the json that allows an admin client to set some specific attributes
for a client. This would require the admin id, its secret, the client id and (probably) the server's address.
A note on style. It's terrible. Meaning that all 4 are included even it the result is pretty stringy, like

admin-get-client-client.json

In which an AC is getting the entire  client record from the server. The reason for this is that there are literally
dozens of scripts and it was felt that a completely predictable approach was better than a more clever one.

The exception is if the target and object are the same, so client commands that get information about the
same client may have the object elided:

client-get-attribute.json

for instance would get the value of an attribute for the given subject client.

It is not intended that you should be running a complete client management setup with these examples, but that
you can see how they work and boilerplate your own togther from them. For one thing, all the client data is just
for demonstration, so there is no real content being transmitted by the examples.

