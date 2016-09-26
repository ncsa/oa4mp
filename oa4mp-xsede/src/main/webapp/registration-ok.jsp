<%--
  User: Jeff Gaynor
  Date: 9/25/11
  Time: 4:26 PM
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head><title>Registration Successful</title></head>
<link rel="stylesheet" type="text/css" media="all" href="xup.css"/>
    <link rel="icon" href="images/favicon.ico" type="image/x-icon"/>
    <link rel="shortcut icon" href="images/favicon.ico" type="image/x-icon"/>
<body>
<div id="topimgfill">
    <div id="topimg"></div>
</div>
<br clear="all"/>

<div class="floatleftbox">
    <div class="boxheader">Registration Successful! The gateway identifier</div>
    <div class="textbox">Here is your gateway identifier:
        <br><br><b>${client.identifier}</b>

        <br><br>IMPORTANT NOTE: It is the gateway's responsibility to store this identifier and use it
	as needed to identify itself. Please keep this in a safe location.
	<p>
        An administrator will contact you once your registration request is approved. You cannot use this
	identifier code until you have been approved by the administrator. This approval will take one to two business days
	for any additional questions please contact the <a href="mailto:help@xsede.org">XSEDE Help Desk</a>.
	<p>
    </div>

    <div class="footer">Please send any questions or comments about this site to
        <a href="mailto:help@xsede.org">help@xsede.org</a>.
    </div>
</div>

</body>
</html>