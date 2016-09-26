<%--
  Really basic error page. There are other error pages that are displayed at times,
  but this is a general one which will be displayed if all else fails.
  Date: Aug 5, 2010
  Time: 2:17:49 PM
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page isErrorPage="true" %>
<html>
<head>
    <title>The XSEDE MyProxy Delegation Service 404 Error Page.</title>
    <link rel="stylesheet" type="text/css" media="all" href="xup.css"/>
    <link rel="icon" href="images/favicon.ico" type="image/x-icon"/>
    <link rel="shortcut icon" href="images/favicon.ico" type="image/x-icon"/>
</head>

<body>
<div id="topimgfill">
    <div id="topimg"></div>
</div>
<br clear="all"/>

<div class="floatleftbox">
    <div class="boxheader">There was a problem servicing your request.</div>

    <div class="textbox">

        A description of the problem reads as follows:
        <br><br>
        <i>
             <%= message %>
        </i>
        <br>
    </div>

    <div class="footer">Please send any questions or comments about this site to
        <a href="mailto:help@xsede.org">help@xsede.org</a>.
    </div>
</div>

</body>
</html>
