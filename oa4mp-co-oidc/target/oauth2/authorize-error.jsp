<%--
  User: Jeff Gaynor
  Date: 9/26/11
  Time: 10:34 AM
  Properties supplied:
    * exception that generated this page
    * client = client associated with this error as ${client}.
    This page should redirect the user to  ${client.errorUri}
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>The Delegation Service 404 Error Page.</title>
</head>

<body>

<h2>There was a problem servicing your request.</h2>

The diagnostic message reads: <i>${exception.message}</i>

<br><br>

<form name="input" action="${client.errorUri}" method="get">
    <input type="submit" value="return to client"/>
</form>

</body>
</html>
