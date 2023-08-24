# OAuth for MyProxy

[![DOI](https://zenodo.org/badge/58557836.svg)](https://zenodo.org/badge/latestdoi/58557836)
[![Javadocs](https://www.javadoc.io/badge/edu.uiuc.ncsa.myproxy/oa4mp-client-api.svg)](https://www.javadoc.io/doc/edu.uiuc.ncsa.myproxy/oa4mp-client-api)
[![NSF-1127210](https://img.shields.io/badge/NSF-1127210-blue.svg)](https://nsf.gov/awardsearch/showAward?AWD_ID=1127210)

Open Authorization for Many People (OA4MP) is an robust OAuth client/server implementation from the [NCSA](https://www.ncsa.illinois.edu/) that provides authorization and delegation software
for science gateways. Initially deployed in 2011, it is a mature, stable and extremely extensible system that is widely used.

## Prerequisites

* Java 11
* [Maven](https://maven.apache.org/) 3.9+
* [Tomcat 9](https://tomcat.apache.org/download-90.cgi)

## Docs

https://oa4mp.org
                 
# Building from sources

There are a couple of ways todo this. You can 
* compile and install OA4MP locally using maven
* do the entire build with artifacts which may then be released (typically on GitHub)
* compile and install with maven, then deploy to Sonatype to be used as depedencies by other prjects

## Gettign the source

You may check out the source from [GitHub](https://github.com/ncsa/oa4mp). This is
cloned into a source directory