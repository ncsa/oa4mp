<%--
  User: Jeff Gaynor
  Date: 9/27/11
  Time: 4:37 PM

    NOTE:This page is supplied as an example and under no circumstances should ever be deployed
  on a live server. It is intended to show control flow as simply as possible.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head><title>Simple client delegation request</title></head>
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
<p>Success!<br><br>
    The redirect uri is<br><br> <a href="${redirectUrl}">${redirectUrl}</a>
    <br><br>
    Click the link to go there....
<br><br>

<ul>
    <li><a href="javascript:unhide('showCert');">Show/Hide private key</a></li>
    <div id="showCert" class="hidden">
        <p>
        <pre>${privateKey}</pre>
    </div>
</ul>
</body>
</html>