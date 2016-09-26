<%--
  User: Jeff Gaynor
  Date: May 27, 2011
  Time: 10:36:41 AM
  Properties included:
     field names:
        * clientName
        * clientEmail
        * clientHomeUrl
        * clientErrorUrl
        * clientPublicKey
        * action
        * request
     Control flow:
        * actionToTake = url to invoke on submitting this form
        * action = name of hidden field containing the request property
        * request = contents of field with the state of this
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>


<html>
<head>
    <title>XSEDE User Portal Request for Science Gateway Delegation Access</title>
    <link rel="stylesheet" type="text/css" media="all" href="xup.css"/>
    <link rel="icon" href="images/favicon.ico" type="image/x-icon"/>
    <link rel="shortcut icon" href="images/favicon.ico" type="image/x-icon"/>
</head>
<body>
<div id="topimgfill">
    <div id="topimg"></div>
</div>
<br clear="all"/>

<div class="floatleftbox">
    <form action="/oauth/register" method="post">
        <div class="boxheader">Welcome to the XSEDE Science Gateway Delegation Access Request Form</div>

        <div class="authbox">
            This page allows you to register your gateway with the XSEDE User Portal
            for delegation using OAuth. To get your gateway approved for delegation
            please fill out the form below. Your request will be evaluated for approval. For more information,
            please make sure you read the
            <a href="http://grid.ncsa.illinois.edu/myproxy/oauth/client/manuals/registering-with-a-server.xhtml"
               target="_blank">Gateway Registration Document</a>.
            <p>
            <table>
                <tr>
                    <td>Gateway Name:</td>
                    <td><input type="text" size="25" name="${clientName}"/></td>
                </tr>
                <tr>
                    <td>Contact email:</td>
                    <td><input type="text" size="25" name="${clientEmail}"/></td>
                </tr>
                <tr>
                    <td>Home URL:</td>
                    <td><input type="text" size="25" name="${clientHomeUrl}"/></td>
                </tr>
                <tr>
                    <td>Error url:</td>
                    <td><input type="text" size="25" name="${clientErrorUrl}"/></td>
                </tr>
                <tr>
                    <td></td>
                    <td><input type="checkbox" name="${clientProxyLimited}" value="true"/><span
                            title="Check this box for delegation of limited proxy certificates for use with Globus Toolkit GridFTP servers. Leave this box unchecked for delegation of general-use X.509 certificates.">Use Limited Proxy Certificates?</span>
                    </td>
                </tr>
                <tr>
                    <td>Public Key:</td>
                    <td>
                        <textarea id="${clientPublicKey}" rows="20" cols="80"
                                  name="${clientPublicKey}">Paste public key here</textarea>
                    </td>
                </tr>
                <tr>
                    <td><input type="submit" value="submit"/></td>
                </tr>
            </table>
            <input type="hidden" id="status" name="${action}"
                   value="${request}"/>
        </div>
    </form>


    <div class="footer">Please send any questions or comments about this site to
        <a href="mailto:help@xsede.org">help@xsede.org</a>.
    </div>

</div>

</body>
</html>