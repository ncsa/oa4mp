<%--
  User: Jeff Gaynor
  Date: 5/20/2024
  Time: 3:10 PM
  This is for the case that the device flow has an existing logon (so no logon page
  has been displayed) but consent is setill required.
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
<%@ page session="false" %>
<html>
<head>
    <title>OA4MP Device Flow Consent Page</title>
    <link rel="stylesheet"
          type="text/css"
          media="all"
          href="static/oa4mp.css"/>
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
<div id="topimgfill">
    <div id="topimg"/>
</div>
<br clear="all"/>
<div class="main">
    <h2>Welcome to the OA4MP Device Flow Consent Page</h2>
    The Client below is requesting access to your account.
    <p>

    <form action="${actionToTake}" method="POST">
        <table width="800" cellspacing="0" border="2">
            <tr>
                <td valign="top">
                    <table border=1>
                        <tr valign="top">
                            <th>Client Information</th>
                        </tr>
                        <tr>
                            <td> The client listed below is requesting access to your
                                account. If you approve, please sign in.
                                <br><br>
                                <i>Name:</i> ${clientName}
                                <br>
                                <i>URL:</i> ${clientHome}
                                <br>
                                <i>Requested Scopes:</i> ${clientScopes}
                            </td>
                        </tr>
                    </table>
                </td>
                <td valign="top">
                    <table width="350" cellspacing="0" cellpadding="0" align="right" border="0">

                        <tr>
                            <td colspan="2">&nbsp;</td>
                        </tr>
                        <tr>
                            <td><input type="submit" value="approve"/></td>
                            <td>
                                <a href="${clientHome}" STYLE="TEXT-DECORATION: NONE"><input type="button"
                                                                                             name="cancel"
                                                                                             value="Cancel"/></a>
                            </td>
                        </tr>


                    </table>
                    <!-- Close sign in table -->
                    <input type="hidden" id="status" name="${action}"
                           value="${actionOk}"/>
                    <input type="hidden" id="token" name="${tokenKey}" value="${authorizationGrant}"/>
                    <input type="hidden" id="state" name="${stateKey}" value="${authorizationState}"/>
                    <input type="hidden" id="page_type" name="page_type" value="consent"/>
                </td>
            </tr>
        </table>
    </form>
</div>
</body>
</html>
