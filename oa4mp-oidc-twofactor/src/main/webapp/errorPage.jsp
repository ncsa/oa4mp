<%--
  Really basic error page. There are other error pages that are displayed at times,
  but this is a general one which will be displayed if all else fails.
  Date: Aug 5, 2010
  Time: 2:17:49 PM
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page isErrorPage="true" %>
<%@ include file="assets/includes/start.html" %>

    <h4>There was a problem servicing your request.</h4>

    <p>A description of the problem reads as follows:</p>
    <p><%= message %></p>

<%@ include file="assets/includes/end.html" %>
