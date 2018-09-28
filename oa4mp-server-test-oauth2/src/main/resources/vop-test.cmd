# A test for the voPersonExternalID configuration script.
# The format of a script is that each comment starts with a #
# An input line ends with a ; (so it may span several lines of text)
# There is an environment for the script for its duration. You may set and get stored values.


# this will allow you to use this long value easily:

setEnv('vo','voPersonExternalID');

# the next line sets the eppn so that the test works.

set('eppn','jgaynor@ncsa.illinois.edu');

# Now we set some IDPs in the runtime environment

setEnv('github','http://github.com/login/oauth/authorize');
setEnv('google','http://google.com/accounts/o8/id');
setEnv('orcid','http://orcid.org/oauth/authorize');


# And the test for LSST. This should set voPersonExternalID to the eppn value above.
xor{
    if[hasClaim('eppn')]then[set('${vo}',get('eppn'))],
    if[hasClaim('eptid')]then[set('${vo}',get('eptid'))],
    if[equals(get('idp'),'${github}')]then[set('${vo}',concat(get('oidc'),'@github.com'))],
    if[equals(get('idp'),'${google}')]then[set('${vo}',concat(get('oidc'),'@accounts.google.com'))],
    if[equals(get('idp'),'${orcid}')]then[set('${vo}',replace(get('oidc'),'http://','https://'))]
};

# During testing, the following line will print out to the console. Note this is only enabled
# during unit tests and will not execute on the server.

echo(concat('The ${vo} has been set to ', get('${vo}')));