<%--
  User: Jeff Gaynor
  Date: 9/25/11
  Time: 6:42 PM
  Properties supplied:
  * clientName = the name of the client
  * clientHome = the home uri of the client
  * AuthUserName = field name containing the user name on submission
  * AuthPassword = field name containing the user's password on submission
  * AuthUserCode = field contining the user code
  * retryMessage = message displayed if the login in fails.
  * userCode = on retry, last attempt so it can be edited.
  * tokenKey = name of hidden field to pass along the authorizationGrant
  * actionToTake = what action that submitting the form invokes.
  * authorizationGrant = the identifier for this transaction
  * action = name of field containing the action the servlet should take
  * actionOk = content of action field in this case telling the service to continue processing.

--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page session="false" %>
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
<h2>Welcome to the OAuth 2.0 for MyProxy device flow authorization page.</h2>
<p>You will need to do your logon plus supply the user code that was given to you
at the start of the interaction. </p>
<p>

<form action="${actionToTake}" method="POST">
    <table width="800" cellspacing="0" border="2">
        <tr>
            <td valign="top">
            </td>
            <td valign="top">
                <table width="350" cellspacing="0" cellpadding="0" align="right" border="0">
                    <tr>
                        <th colspan="2">Please sign in</th>
                    </tr>
                    <tr>
                        <td>Username</td>
                        <td><input type="text" size="25" name="${AuthUserName}"
                                   value="${userName}"/></td>
                    </tr>
                    <tr class="${(userName == "" || userName == null)? "unhidden" : "hidden"}">
                        <td>Password</td>
                        <td>
                            <input type="password" size="25" name="${AuthPassword}"/>
                        </td>
                    </tr>
                    <tr>
                        <td>User code</td>
                        <td><input type="text" size="25" name="${AuthUserCode}"
                                   value="${userCode}"/></td>
                    </tr>
                    <tr>
                        <td colspan="2">&nbsp;</td>
                    </tr>
                    <tr>
                        <td><input type="submit" value="Sign In"/></td>
                        <td>
                            <a href="${clientHome}" STYLE="TEXT-DECORATION: NONE"><input type="button"
                                                                                         name="cancel"
                                                                                         value="Cancel"/></a>
                        </td>
                    </tr>
                    <tr>
                        <td colspan="2"><b><font color="red">${retryMessage}</font></b></td>
                    </tr>

                </table>
                <!-- Close sign in table -->
                <input type="hidden" id="status" name="${action}"
                       value="${actionOk}"/>
                <input type="hidden" id="token" name="identifier" value="${identifier}"/>
                <input type="hidden" id="counter" name="counter" value="${count}"/>

            </td>
        </tr>
    </table>
</form>

</body>
</html>
