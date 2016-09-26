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
<%@ include file="assets/includes/start.html" %>

<p>
The Client or Service below is requesting access to your account. If you approve,
please sign in with your username and password.
</p>

<p>
<strong>Name:</strong> ${clientName}
<br>
<strong>URL:</strong> ${clientHome}
</p>

        <form action="${actionToTake}" method="POST">
          <table style="border-spacing:5px;border-collapse:separate">
            <tr>
              <th style="font-size:150%">Username:</th>
              <td><input type="text" size="50" name="${AuthUserName}"/></td>
            </tr>
            <tr>
              <th style="font-size:150%">PIN + tokencode:</th>
              <td><input type="password" size="50" name="${AuthPassword}"/></td>
            </tr>
            <tr>
              <th colspan="2">
                <input type="submit" value="Sign In"/>
                <a href="${clientHome}/"><input type="button"
                                               name="cancel"
                                               value="Cancel"/></a>
              </th>
            </tr>
          </table>
          <p><font color="red">${retryMessage}</font></p>
          <input type="hidden" id="status" name="${action}" value="${actionOk}"/>
          <input type="hidden" id="token" name="${tokenKey}" value="${authorizationGrant}"/>
        </form>

<%@ include file="assets/includes/end.html" %>
