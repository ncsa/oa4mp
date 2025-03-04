<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<html>
<head>
    <title>MyProxy Delegation Service Client Registration Page</title>
</head>
<body>
<form action="${actionToTake}" method="post">
    <h2>Welcome to the OA4MP Client Registration Page</h2>

    <p>This page allows you to register your client with OA4MP.
        To get your client approved,
        please fill out the form below. Your request will be evaluated for approval. For more information,
        please make sure you read the
        <a href="https://oa4mp.org/client/manuals/registering-with-an-oauth2-server.html"
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
            <td>Home URL:</td>
            <td><input type="text" size="25" name="${clientHomeUrl}" value="${clientHomeUrlValue}"/></td>
        </tr>
        <tr>
            <td>Callback URLs:</td>
            <td>
                    <textarea id="${callbackURI}" rows="5" cols="80"
                              name="${callbackURI}">${callbackURIValue}</textarea>
            </td>
        </tr>
        <tr>
            <td>Scopes:</td>
            <td>
                <c:forEach items="${scopes}" var="scope">
                    <input type="checkbox"
                           name="chkScopes"
                           value="${scope}"
                        <c:set var="xxx" scope="session" value="${scope}"/>
                           <c:if test="${xxx == 'openid'}">checked="checked"</c:if>
                    >${scope}&nbsp;
                </c:forEach>
            </td>
        </tr>

        <tr>
            <td ${rtFieldVisible}>Refresh Token lifetime:</td>
            <td ${rtFieldVisible}><input type="text" size="25" name="${rtLifetime}" value="${rtLifetimeValue}"/>(in
                seconds - leave blank for no refresh tokens.)
            </td>
        </tr>
        <tr>
            <td>Issuer (optional):</td>
            <td><input type="text" size="25" name="${issuer}" value="${issuerValue}"/></td>
        </tr>
        <tr>
            <td>Public Key (optional):</td>
            <td>
                       <textarea id="${clientPublicKey}" rows="20" cols="80"
                                 name="${clientPublicKey}">${clientPublicKeyValue}</textarea>
            </td>
        </tr>
        <tr>
            <td></td>
            <td><input type="checkbox" name="${clientProxyLimited}" ${clientProxyLimitedValue} /><span
                    title="Check this box for delegation of limited proxy certificates for use with Globus Toolkit GridFTP servers. Leave this box unchecked
                           for delegation of general-use X.509 certificates.">Use Limited Proxy Certificates?</span>
            </td>
        </tr>
        <tr>
            <td></td>
            <td><input type="checkbox" name="${clientIsPublic}" ${clientIsPublicValue} /><span
                    title="Check this box if the client is to be public, i.e., limited access, no certificates allowed and no secret needed.
                          If you are not sure what this is, do not check it or ask for help.">Is this client public? In that case the only allowed scope is openid.</span>
            </td>
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

</body>
</html>