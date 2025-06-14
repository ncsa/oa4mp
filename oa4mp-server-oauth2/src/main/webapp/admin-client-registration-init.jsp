<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page session="false" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<html>
<head>
    <title>OA4MP Administrative Client Registration Page</title>
    <link rel="stylesheet"
          type="text/css"
          media="all"
          href="static/oa4mp.css"/>
</head>
<body>
<div id="topimgfill">
    <div id="topimg"/>
</div>
<br clear="all"/>
<div class="main">
<form action="${actionToTake}" method="post">
    <h2>Welcome to the MyProxy Delegation Administrative Client Registration Page</h2>

    <p>This page allows you to register your administrative client with the
        MyProxy delegation service that supports the OIDC/OAuth 2. To get your client approved,
        please fill out the form below. Your request will be evaluated for approval. For more information,
        please make sure you read the
        <a href="http://grid.ncsa.illinois.edu/myproxy/oauth/client/manuals/registering-with-an-oauth2-server.xhtml"
           target="_blank">Registering a Client with an OAuth 2 server</a> document.
    </p><br>
    <table>
        <tr>
            <td>Client Name:</td>
            <td><input type="text" size="25" name="${clientName}" value="${clientNameValue}"/></td>
        </tr>
        <tr>
            <td>Contact email:</td>
            <td><input type="text" size="25" name="${clientEmail}" value="${clientEmailValue}"/></td>
        </tr>

        <tr>
            <td>Issuer (optional):</td>
            <td><input type="text" size="25" name="${issuer}" value="${issuerValue}"/></td>
        </tr>
        <tr>
            <td><input type="submit" value="submit"/></td>
        </tr>
        <tr>
            <td colspan="2"><b><font color="red">${retryMessage}</font></b></td>
        </tr>
    </table>
    <input type="hidden" id="status" name="${action}"
           value="${request}"/>
</form>
</div>
</body>
</html>