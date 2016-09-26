<%--
  User: Jeff Gaynor
  Date: 9/25/11
  Time: 4:56 PM
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head><title>XSEDE MyProxy Delegation Service Registration Error Page</title></head>
<link rel="stylesheet" type="text/css" media="all" href="xup.css"/>
<link rel="icon" href="images/favicon.ico" type="image/x-icon"/>
<link rel="shortcut icon" href="images/favicon.ico" type="image/x-icon"/>
<body>
<div id="topimgfill">
    <div id="topimg"></div>
</div>
<br clear="all"/>


<div class="floatleftbox">

    <div class="boxheader">Registration Error</div>

    <div class="textbox">There was a problem processing your request. Please check your arguments carefully and try again.

        <p>The diagnostic message reads: <i>${exception.message}</i>
        <br><br>
    </div>


    <div class="footer">Please send any questions or comments about this site to
        <a href="mailto:help@xsede.org">help@xsede.org</a>.
    </div>

</div>


</body>
</html>