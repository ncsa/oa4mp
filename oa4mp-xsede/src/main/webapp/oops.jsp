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
    <title>Client Request Error</title>
    <link rel="stylesheet" type="text/css" media="all" href="xup.css"/>
    <link rel="icon" href="images/favicon.ico" type="image/x-icon"/>
    <link rel="shortcut icon" href="images/favicon.ico" type="image/x-icon"/>
</head>

<body>
<div id="topimgfill">
    <div id="topimg"></div>
</div>
<br clear="all"/>

<div class="boxheader">Server Error</div>

<div class="textbox">There was a problem processing your request. Please check your arguments carefully and try again.

    <p>The diagnostic message reads: <i>${exception.message}</i>
        <br><br>
</div>


<div class="footer">Please send any questions or comments about this site to
    <a href="mailto:help@xsede.org">help@xsede.org</a>.
</div>

</body>
</html>
