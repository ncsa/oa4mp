<%--
  Really basic error page. There are other error pages that are displayed at times,
  but this is a general one which will be displayed if all else fails.
  Date: Aug 5, 2010
  Time: 2:17:49 PM
  Properties included:
  * exception = the exception that generated this page if there is one.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page isErrorPage="true" %>
<html>
<head>
    <title>The Delegation Service Error Page.</title>
</head>

<body>
<h2>There was a problem servicing your request.</h2>

<%
    String message = exception.getMessage();
    if (-1 < exception.getMessage().toLowerCase().indexOf("myproxy")) {
        message = "Error from MyProxy. Be sure that you used the correct username and password.";
    }
%>
A description of the problem reads as follows:
<br><br>
<i>
    <%= message %>
</i>
<br>

</body>
</html>
