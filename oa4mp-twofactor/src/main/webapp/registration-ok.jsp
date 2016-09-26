<%--
  User: Jeff Gaynor
  Date: 9/25/11
  Time: 4:26 PM
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ include file="assets/includes/start.html" %>

    <h4>Registration Successful!</h4>
    <div class="textbox">
        <p>Here is your client identifier:</p>

        <p><b>${client.identifier}</b></p>

        <p>IMPORTANT NOTE: It is the client's responsibility to store this identifier and use it
	         as needed to identify itself. Please keep this in a safe location.</p>

        <p> An administrator will contact you once your registration request is approved. You
        cannot use this identifier code until you have been approved by the administrator. This
        approval will take one to two business days. For any additional questions please contact
        the <a href="mailto:help@ncsa.illinois.edu">Help Desk</a>.</p>
    </div>

<%@ include file="assets/includes/end.html" %>
