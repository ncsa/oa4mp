# OAuth for MyProxy

[![DOI](https://zenodo.org/badge/58557836.svg)](https://zenodo.org/badge/latestdoi/58557836)
[![Javadocs](https://www.javadoc.io/badge/edu.uiuc.ncsa.myproxy/oa4mp-client-api.svg)](https://www.javadoc.io/doc/edu.uiuc.ncsa.myproxy/oa4mp-client-api)
[![NSF-1127210](https://img.shields.io/badge/NSF-1127210-blue.svg)](https://nsf.gov/awardsearch/showAward?AWD_ID=1127210)

Open Authorization for Many People (OA4MP) is an robust OAuth client/server implementation from the [NCSA](https://www.ncsa.illinois.edu/) that provides authorization and delegation software
for science gateways. Initially deployed in 2011, it is a mature, stable and extremely extensible system that is widely used.

## Prerequisites

* Java 11
* [Maven](https://maven.apache.org/) 3.5+
* [Tomcat 9](https://tomcat.apache.org/download-90.cgi)

## Docs

https://oa4mp.org

# License

Please see the [NCSA license](https://github.com/cilogon/oauth2-cilogon/blob/master/LICENSE) for details

                 
# Building from sources

## Getting the sources

You may check out the source from [GitHub](https://github.com/ncsa/oa4mp). This is
cloned into `$NCSA_DEV_INPUT`. At the end of the cloning, you should have `$NCSA_DEV_INPUT/oa4mp`.
A typical sequence would be
```
$>export NCSA_DEV_INPUT=/path/to/ncsa/git
$>cd $NCSA_DEV_INPUT
$>git clone (whatever you want)
$>cd oa4mp
```

## How to compile, deploy etc.

There are a couple of ways todo this. You can

1. compile and install OA4MP locally using just maven
2. do the entire build with artifacts which may then be released (typically on GitHub)
3. compile and install with maven, then deploy to Sonatype to be used as depedencies by other projects
                                                                                                       
## Required environment variables

There are a few environment variables you should define before doing anything. These are used everywhere.

* NCSA_DEV_INPUT - the root for the sources
* NCSA_DEV_OUTPUT - where any created artifacts go
* JAVA_HOME - this is required by maven or it won't know where to find the javadoc tools

# Building by the numbers

## Updating the release version

Do a global replace of the SNAPSHOT tag with the version you are creating. 
E.g. replace `5.5` with `5.3.5`. Note this must be global in all files since this is used extensively in 
the documentation. If you are updating teh website, you do not need to update 
anything in `$NCSA_DEV_INPUT/oa4mp/docs` which will be replaced shortly. 


## Option 1

From the checked out directory `$NCSA_DEV_INPUT/oa4mp` issue

`mvn clean install`

which will download a ton of stuff and build OA4MP. This may, depending on your 
version of Maven, have the occasional warning like "illegal reflective operation"
which is benign. What that means is that one of the dependencies squirreled away is
not quite up to date. Ignore these. As long as the build completes, you are fine

## Option 2

From the checked out directory `$NCSA_DEV_INPUT/oa4mp` issue

`./build.sh`

which will run Maven (see note in Option 1 for possible warnings) then create deploayment
artifacts. Note that the output from the maven build will be put into the file
`maven.log` and should be consulted if there is an error. The artifact will reside in `$NCSA_DEV_OUTPUT/client` for things related to the
OA4MP client and `$NCSA_DEV_OUTPUT/server` for server related items. Typical list of each 
follows.

### Client artifacts

| Name         | Description                                                         |
|--------------|---------------------------------------------------------------------|
| client2.war  | The client war to be deployed under Tomcat                          |
 | client-X.sql | The SQL creation script for database X, e.g. MySQL, Derby, Postgres |

### Server artifacts

| Name                | Description                                                                    |
|---------------------|--------------------------------------------------------------------------------|
| clc                 | script to run the CLC (command line client)                                    |
| clc.jar             | runnable jar for the Command Line Client                                       | 
| cli                 | script to run the CLI (command line interface, the chief admin tool for OA4MP) |
| cli.jar             | runnable jar for the CLI                                                       |
| jwt.jar             | runnable jar for JSON web keys                                                 |
| jwt-scripts.tar     | scripts for the JSON web keys utility                                          |
| oa4mp-X.sql         | SQL creation scripts for database X, e.g., mysql, derby, etc.                  |
 | oa4mp-X.template    | sample subject and message templates for email notifications under OA4MP       |
| oauth2.war          | the deployable war for Tomcat. This is actually OA4MP.                         |
 | oidc-cm-scripts.tar | command line utilities and sample scripts for using the client management API  |

You may or may not want to commit these to GitHub. If so, you must have commit privileges. 
You should create a release in GitHub and upload these files. 

## Option 3

In this case, you must be registered at Sonatype as an administrator for OA4MP and have uploaded your
public keys for signing maven artifacts. The basic steps are

1. Enable gpg signing in the top-level pom, as well as in the oa4mp server and client poms.
2. Run `mvn clean install` first.
3. Run `mvn deploy` after install has completed

The reason we do not run `mvn clean install deploy` or some such is that the creation of the
various  jars is actually complex and it is best done in a separate stage, since the automatic
resolution maven uses tends to have multiple jars created then deploy complains.

# Building and deploying the website

You can also update the website. You must be able to commit to Github to do this. The basic way this works is that you 
1. Do a global replace of the SNAPSHOT tag with the version you are creating. E.g. replace `5.5` with `5.3.5`. Note this must be global in all files since this is used extensively in the documentation. You do not need to update anything in `$NCSA_DEV_INPUT/oa4mp/docs` which will be replaced shortly. 
2. run the `build.sh` script to create all of the basic documentation 
3. run `$NCSA_DEV_INPUT/oa4mp-website/make-website.sh` which creates the entire website and stick it in `$NCSA_DEV_INPUT/oa4mp/docs`
4. commit everything to Git
5. in GitHub, go to the settings page for the project and go to the Pages. You can set the version for Pages to whatever you just committed

The update is (relatively) live in the sense that it will take a few minutes. If yo go to the main landing page for [OA4MP](https://oa4mp.org)
you should see the new version on the page.