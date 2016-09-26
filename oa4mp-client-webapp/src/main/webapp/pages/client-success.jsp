<%--
  User: Jeff Gaynor
  Date: 9/27/11
  Time: 4:58 PM

    NOTE:This page is supplied as an example and under no circumstances should ever be deployed
  on a live server. It is intended to show control flow as simply as possible.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head><title>Simple client success page.</title></head>
<style type="text/css">
    .hidden {
        display: none;
    }

    .unhidden {
        display: block;
    }
</style>
<script type="text/javascript">
    function unhide(divID) {
        var item = document.getElementById(divID);
        if (item) {
            item.className = (item.className == 'hidden') ? 'unhidden' : 'hidden';
        }
    }
</script>
<body>
<h1>Success!</h1>

<p>The subject of the first cert is<br><br> ${certSubject}
    <br><br>and the user id found for this request was <b>${username}</b>

<p>You have successfully requested a certificate from the server.<br>

<ul>
    <li><a href="javascript:unhide('showCert');">Show/Hide certificates</a></li>
    <div id="showCert" class="hidden">
        <p>
        <pre>${cert}</pre>
    </div>
</ul>
<form name="input" action="${action}" method="get"/>
<input type="submit" value="Return to client"/>
</form>
</body>
</html>