This directory contains some QDL tests for the authorization headers
and remote user support under Tomcat.

Prerequisites
¯¯¯¯¯¯¯¯¯¯¯¯¯
The server must be configured to accept Tomcat as the authorization
mechanism.

         Tomcat install : $CATALINA_HOME
The root of the sources : $OA4MP_DEV=/home/ncsa/dev/ncsa-git/oa4mp on my system,
  The webapp resides at : $WEBAPP=$OA4MP_DEV/oa4mp-server-oauth2/src/main/webapp/WEB-INF


This means

(1) Make sure that Tomcat is configured for users. This means

    $CATALINA_HOME/tomcat_users.xml

    has users listed

    <tomcat-users xmlns="http://tomcat.apache.org/xml"
                  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                  xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
                  version="1.0">

         <role rolename="tomcat"/>
         <role rolename="oa4mp"/>

         <user username="jeff"    password="XXXXXXXX" roles="tomcat,oa4mp"/>
         <user username="jgaynor" password="YYYYYYYY" roles="tomcat,oa4mp"/>
      </tomcat-users>

      These roles need to correspond to the roles in the web.xml file later.

(2) Set the server configuration to use Tomcat as the authorization servlet.
    This means setting the authorizationServlet element to:

   <authorizationServlet useHeader="true"
                         requireHeader="true"
                         headerFieldName="REMOTE_USER"/>

(3) In the $WEBAPP/web.xml
    file, there are two large sections for

    <security-constraint>

    Each is needed. The only difference is one has this line

           <url-pattern>/device</url-pattern>

    vs.

           <url-pattern>/authorize</url-pattern>

    both are needed and resp. control if the device flow and auth code flow
    are using Tomcat.

    N.B. As a convenience in that directory,

    $WEBAPP/proxy.xml = web.xml that does proxying
    $WEBAPP/remote-user.xml = web.xml that enables remote user

    Copy the contents of whichever you need to web.xml

    Testing
    ¯¯¯¯¯¯¯
    There is a single client with ID localhost:test/headers which is used and references
    a QDL script in $OA4MP_DEV/server-admin/src/main/resources/qdl/ui-test/header-test.qdl