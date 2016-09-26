<%--
  User: Jeff Gaynor
  Date: 9/26/11
  Time: 10:34 AM
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page isErrorPage="true" %>
<%@ include file="assets/includes/start.html" %>

    <h4>There was a problem servicing your request.</h4>

    <p>The diagnostic message reads:</p>
    <p>${exception.message}</p>

    <form name="input" action="${client.errorUri}" method="get">
        <input type="submit" value="Return to Client"/>
    </form>

<%@ include file="assets/includes/end.html" %>
