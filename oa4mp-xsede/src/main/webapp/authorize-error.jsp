<%--
  User: Jeff Gaynor
  Date: 9/26/11
  Time: 10:34 AM
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
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

        The diagnostic message reads: <i>${exception.message}</i>

        <br><br>

        <form name="input" action="${client.errorUri}" method="get">
            <input type="submit" value="return to gateway"/>
        </form>

    </div>


    <div class="footer">Please send any questions or comments about this site to
        <a href="mailto:help@xsede.org">help@xsede.org</a>.
    </div>
</div>
<%--floatleftbox--%>


</body>
</html>
