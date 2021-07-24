File for GA4GH passports. A passport is a set of JWTs included in the user info for the
person. It is pretty simple to add this in QDL.

The protocol is to set a scope in the access token (which is a JWT) which the user endpoint
will later read. If the scopes is there, a passport is issued.

   ga4ga/at.qdl - script that sets ga4gh passport scope in the access token. Used in
                  token, refresh and exchange phases.
ga4gh/ga4gh.qdl - create the passports. Used in the user info phase.

So have your script load at.qdl, then either set ga4gh.qdl to load in the
user info phase or if you need other processing, just load it.