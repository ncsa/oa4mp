<%--
  User: Jeff Gaynor
  Date: 9/25/11
  Time: 4:56 PM
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page isErrorPage="true" %>
<%@ include file="assets/includes/start.html" %>

    <h4>There was a problem processing your request.</h4>

    <p>Please check your arguments carefully and try again.</p>

    <p>The diagnostic message reads:</p>
    <p>${exception.message}</p>

<%@ include file="assets/includes/end.html" %>
