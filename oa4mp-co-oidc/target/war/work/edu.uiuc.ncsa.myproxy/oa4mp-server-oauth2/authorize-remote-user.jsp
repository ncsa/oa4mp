<%--
  User: Jeff Gaynor
  Date: 9/25/11
  Time: 6:42 PM
  Properties supplied:
  * clientName = the name of the client
  * clientHome = the home uri of the client
  * AuthUserName = field name containing the user name on submission
  * AuthPassword = field name containing the user's password on submission
  * retryMessage = message displayed if the login in fails.
  * tokenKey = name of hidden field to pass along the authorizationGrant
  * actionToTake = what action that submitting the form invokes.
  * authorizationGrant = the identifier for this transaction
  * action = name of field containing the action the servlet should take
  * actionOk = content of action field in this case telling the service to continue processing.

--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>MyProxy Delegation Portal Authorization Page</title>

</head>
<style type="text/css">
    .hidden {
        display: none;
    }

    .unhidden {
        display: table-row;
    }
</style>
<body>
<h2>Welcome to the OAuth 2.0 for MyProxy Client Authorization Page</h2>
The Client below is requesting access to your account. If you approve,
please accept, otherwise, cancel.
<p>

<form action="${actionToTake}" method="POST">

    <table border=1>
        <tr valign="top">
            <th>Client Information</th>
        </tr>
        <tr>
            <td> The client listed below is requesting access to your
                account. If you approve, please accept.
                <br><br>
                <i>Name:</i> ${clientName}
                <br>
                <i>URL:</i> ${clientHome}
            </td>
        </tr>
        <tr>
            <td>
                <input type="submit" style="float: left;" value="Accept"/>
                <input type="button" style="float: right;" name="cancel" value="Cancel"/></a>
            </td>
        </tr>
        <tr>
            <td colspan="2"><b><font color="red">${retryMessage}</font></b></td>
        </tr>
    </table>

    <!-- Unhide this when you want to support it. All the machinery is in place.
                     <tr>
                        <td>Refresh token lifetime</td>
                        <td><input type="text" size="25" name="${AuthRTL}"
                                   value="${rtLifetime}"/></td>
                    </tr>
                    -->
    <!-- Close sign in table -->
    <input type="hidden" id="status" name="${action}"
           value="${actionOk}"/>
    <input type="hidden" id="token" name="${tokenKey}" value="${authorizationGrant}"/>
    <input type="hidden" id="state" name="${stateKey}" value="${authorizationState}"/>

</form>

</body>
</html>
