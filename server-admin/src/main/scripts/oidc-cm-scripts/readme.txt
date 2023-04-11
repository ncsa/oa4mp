Using the command line tools.

You need to have a valid admininstrative client (that is to say, registered and approved) and the identifier
and admin secret. The scripts here allow for all the operations listed in RFC 7591 and 7592, viz., that
you can create, update, list and delete a client. Since these comprise a restful API
(so the HTTP methods are overloaded to do operations om the client,
e.g., delete,  result in deleting a client), each script supports a single method. There are of the
form cm-X.sh where X is a method, put, get, delete, post. Other HTTP methods are not supported. In a nutshell:

get = read a client
post = create a client
put = modify a client
delete = remove a client

The tricky bits are getting the headers right. Generally the way these scripts work is that you set some environment
variables then invoke the scripts with possibly an argument (which is the name of a file containing JSON). The
responses vary from being JSON objects to being simple status codes.

Administrative clients are allowed to create (and therefore approve) regular clients. Having an admin client implies
that the request was vetted. Admin clients can only perform administrative tasks. So they cannot request, e.g.
user information or initiate an OAuth/OIDC flow.

For all scripts you need to set
ADMIN_ID = the identifier you received at registration
ADMIN_SECRET = the secret you received at registration
REGISTRATION_URI = (get, put, delete) the specific endpoint (usually with some embedded information) for this client
SERVER = (post) the endpoint for creating a new client.

These are set in the script cm-setenv.sh which is read before each script is invoked (so be sure you have the right
values there since whatever is in that script will override your current environment). Feel free to change this
behavior as it suits you.

A set of examples for each script.

**A POST example -- creating a brand new client

In this example, we create a new client. Note that this uses the "minimal.json" object which is the absolute
minimum amount of information a client request may have: A name and a set of redirects. There is also a comment
attribute, but this is for readability and is completely ignored by the server. Assuming that ADMIN_ID, ADMIN_SECRET
and SERVER have been set

>export ADMIN_SECRET="your secret goes here"
>export ADMIN_ID="you id goes here'
>export SERVER=https://dev.cilogon.org/oauth2/oidc-cm
>./cm-post minimal.json
{
 "client_id":"oa4mp:/client_id/3da958ee9bf53cf4183302c890f4f517",
 "client_secret":"AC5LhEgXQUU_Gu91wL-eFLw8l8Jp54p4p1Ki2xrnLCfYlT",
 "client_id_issued_at":1571341138,
 "client_secret_expires_at":0,
 "registration_client_uri":"https://dev.cilogon.org/oauth2/oidc-cm?client_id=oa4mp:/client_id/3da958ee9bf53cf4183302c890f4f517"
}

(Formatted for ease of reading.) A few things to note is that you get a client id and secret **for the new client**.
On top of that, you get the "registration_client_uri" which is the endpoint with the id that allows you to
manage this specific client. For the other scripts, this is exactly the REGISTRATION_URI
variable. More arguments in your json file will result in more information in the response. Of
course, the id and secret will be different if you run this.

At the end of this call, you have an approved client with this id and this secret and may use it for OIDC
flows. Note the rerunning the exact same call repeatedly will simply cause more clients, all with different secrets
and ids, to be generated on the server.

**A GET example -- reading a client

>export REGISTRATION_URI="https://..."
>./cm-get.sh
{
 "registration_client_uri":"https://dev.cilogon.org/oauth2/oidc-cm?client_id=oa4mp:/client_id/3da958ee9bf53cf4183302c890f4f517",
  "client_id":"oa4mp:/client_id/3da958ee9bf53cf4183302c890f4f517",
  "client_name":"My Example",
  "redirect_uris":["https://client.example.org/callback"],
  "grant_types":["authorization_code"],
  "scope":["openid"],
  "client_id_issued_at":1571348271,
  "comment":"This is a the minimal request object required for creation: a set of URIs and a name"
}

A few things to note about the response. We do NOT return the secret since, once more, we only store a hash of
and do not have it. Also, the first example did not specify any scopes and (since this request is to an OIDC server)
only the openid scope is issued. If the OA4MP server is not configured to be OIDC compliant, no scopes will be returned.
Finally, the comment (and any other unknown parameters) in the request are ignored, but preserved and returned.

**A GET example -- retrieving all the clients created by the administrative client

Note that not setting the REGISTRATION_URI before running the cm-get.sh script will result in retrieving all the clients
created by the admininstrative client identified through ADMIN_ID and ADMIN_SECRET.

>./cm-get.sh
{
 'clients':
  [
   {
    "registration_client_uri":"https://dev.cilogon.org/oauth2/oidc-cm?client_id=oa4mp:/client_id/3da958ee9bf53cf4183302c890f4f517",
    "client_id":"oa4mp:/client_id/3da958ee9bf53cf4183302c890f4f517",
    "client_name":"My Example",
    "redirect_uris":["https://client.example.org/callback"],
    "grant_types":["authorization_code"],
    "scope":["openid"],
    "client_id_issued_at":1571348271,
    "comment":"This is a the minimal request object required for creation: a set of URIs and a name"
   }
  ]
}

************************************************************
Comment on uploading cfg elements and extra attributes.
************************************************************
If you upload any attributes that are not known to the spec, they will be put in an attribute we manage named "cfg".
If you are uploading a client configuration to do LDAP queries or what not, then that goes in the "cfg"
attribute. There is an example of this in the supplied create-extra.json file. This specifies the "cfg"
element and there are two extra attributes as well,  "extra_attribute1" and  "extra_attribute2".

Note that if you create a client using this example, the cfg is returned with  "extra_attribute1" and  "extra_attribute2"
included in it. Generally, just put everything in the "cfg" attribute.

A final caveat about sending "cfg" (or for that matter anything) is that as per the spec, missing attributes
in the PUT will delete the attributes on the server (!) Be sure you send everything, expecially the "cfg".
When in doubt, it never hurt to go a GET and use twiddle that.


**A PUT example -- updating a client

There is a minimal example JSON object to demonstrate this called update.json

>export REGISTRATION_URI="https://..."
>./cm-put.sh update.json

The response is identical to issuing a GET:

{
 "registration_client_uri":"https://dev.cilogon.org/oauth2/oidc-cm?client_id=oa4mp:/client_id/3da958ee9bf53cf4183302c890f4f517",
 "client_id":"oa4mp:/client_id/3da958ee9bf53cf4183302c890f4f517",
 "client_name":"New Test name",
 "redirect_uris":["https://client.example.org/callback","https://client.example.org/callback2"],
 "grant_types":["authorization_code"],
 "scope":["openid"],
 "client_id_issued_at":1571350405
}

****************************************
A comment on secrets, old and new
****************************************
If the update contains the client secret, then, as per the spec,  it will be verified and
if it does not match what is on the server, the request will be
rejected. If you do not send a secret, then no check is made.

If you lose the secret or want to change it, there is no way to really issue a new one except to
re-register the client. In that case you will get an entirely new id for this client.

** Public clients
A public client has a scope of openid only and no password. These are assumed to be
public, meaning that they are distributed as parts of other systems (like kubernetes)
and a large number of users can have near anonymous access with them. If you try
to add scopes to a public client, this will be rejected outright because of the public nature -- you
really don't want to change a public client over to something else. In that case, register a new client
with the scopes you want.


**A DELETE example -- removing a client

>export REGISTRATION_URI="https://....."
>./cm-delete.sh

(no output unless there is an error). One point to make here is the expected behavior. The response from this script means
that there is no client with the given id on the server any more. If such a client did not exist in the first place
the response will be the same as if you deleted and existing client. All this call does is ensure there is no such client
on the server.

** Cookbook for running the supplied scripts.

Once the toolkit is unpacked cd to its directory. Every time you run a command , a file named input.json with
your argument is created and the response is stored in output.json.

0. Register an admin client and get it approved.

1. Edit the cm-setenv.sh script. Set the following (these lines are commented out, so uncomment and set the values
   a. SERVER = the server where you registered your admin client
   b. ADMIN_ID = the identifier you got at registration.
   c. ADMIN_SECRET = the secret you got at registration.

   Everything should now run out of th current directory without change.

2. Edit any create scripts. Templates are
   a. create.json = basic template with a lot of properties set.
   b. minimal.json = the actual minimal JSON blob you can use and successfully create a client
   c. create2.json = another minimal example, with scopes and email
   d. create-extra.json = A more complete example with grant types and such.

   Henceforth, it is assumed your JSON is included in my-confg.json

3. Issue

   ./cm-post.sh my-confg.json

   to create your client. Be sure to read and handle the response, which is also stored in
   output.json.

4. You have two options with set the REGISTRATION_URI in the cm-setenv.sh script OR issue

   export REGISTRATION_URI=....

   which only makes it available in the current session. If you have a lot of clients, then you
   probably want to reset it as needed (so you aren't just trying to update same one over and
   over), but if you have only one, then by all means set it.

5. From this point forward, you may issue
   ./cm-get.sh = gets the current client
   ./cm-post-sh my-config.json = update the current client to have the values in this file
   ./cm-delete.sh = deletes this client.

