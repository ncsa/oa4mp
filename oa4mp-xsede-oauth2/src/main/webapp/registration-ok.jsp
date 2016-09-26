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
    <div class="boxheader">Registration Successful!</div>
    <div class="textbox">Here is your gateway/client identifier:
        <br><br><b>${client.identifier}</b>
    <div class="textbox">Here is your gateway/client secret:
        <br><br><b>${client.secret}</b>

        <br><br>IMPORTANT NOTE: It is the gateway's/client's responsibility to store this identifier and secret securely. Your client will need to use it
	as needed to identify itself. Please keep this in a safe location. If you lose the secret, you will have to
re-regisiter. Be sure you copy the secret without line breaks (which some browsers will insert) or you will
get an invalid secret.
	<p>
        An administrator will contact you once your registration request is approved. You cannot use this
	identifier code until you have been approved by the administrator. This approval will take one to two business days.
	For any additional questions please contact the <a href="mailto:help@xsede.org">XSEDE Help Desk</a>.
	<p>
    </div>

    <div class="footer">Please send any questions or comments about this site to
        <a href="mailto:help@xsede.org">help@xsede.org</a>.
    </div>
</div>

</body>
</html>
