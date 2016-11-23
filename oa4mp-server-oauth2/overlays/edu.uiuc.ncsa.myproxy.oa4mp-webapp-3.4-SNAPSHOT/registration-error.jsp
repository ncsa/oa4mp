<%--
  User: Jeff Gaynor
  Date: 9/25/11
  Time: 4:56 PM
  Properties included:
  * exception = the exception that caused this page to be displayed.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head><title>Registration Error Page</title></head>
<body>

<h2>Registration Error</h2>

There was a problem processing your request. Please check your arguments carefully and try again.<br><br>

<p>The diagnostic message reads: <i>${exception.message}</i>
</body>
</html>