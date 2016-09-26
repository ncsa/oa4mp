
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page isErrorPage="true" %>
<%@ page import="java.io.*" %>
<%@ page import="java.net.InetAddress" %>
<%@ page import="java.util.*" %>
<%@ page import="javax.mail.*" %>
<%@ page import="javax.mail.internet.*" %>
<%@ page import="javax.activation.*" %>
<%@ page import="edu.uiuc.ncsa.security.core.util.HostUtil" %>

<%--
    By Terry Fleury. This sends email notifications on its own and if set as an error
    page in the web.xml file will catch any error and process it.
--%>
<%!
    String mailto      = "alerts@cilogon.org";
    String mailsubject = "Error caught by Tomcat on "; // + hostname
    String mailsmtp    = "smtp.ncsa.uiuc.edu";

    void sendEmail(String body, String host) {
        Properties props = System.getProperties();
        props.put("mail.host",mailsmtp);
        props.put("mail.transport.protocol","smtp");
        Session mailSession = Session.getDefaultInstance(props,null);
        mailSession.setDebug(false); // Do not echo debug info
         
        try {
            Message msg = new MimeMessage(mailSession);
            InternetAddress[] address = {new InternetAddress(mailto)};
            msg.setRecipients(Message.RecipientType.TO,address);
            msg.setSubject(mailsubject + host);
            msg.setSentDate(new Date());
            msg.setText(body);
            Transport.send(msg);
        } catch (Exception e) {
        }
    }
%>

<html>
<head>
<title>
<%= application.getServerInfo() %> - Error Report
</title>
</head>

<body>
<%
    ErrorData ed = null;
    if (pageContext != null) {
        try {
            ed = pageContext.getErrorData();
        } catch (NullPointerException e) {
            // If the error page was accessed directly, a NullPointerException
            // is thrown at (PageContext.java:514). So catch it and ignore it. 
            // It effectively means we can't use the ErrorData.
        }
    }

    if (ed != null) {
        String remoteAddr = request.getRemoteAddr();
        String er = "Error Report - " + application.getServerInfo() + "\n";
        er       += "------------\n";
        er += "Error  : " + ed.getStatusCode() + "\n";
        er += "Host   : " + request.getServerName() + "\n";
        er += "Client : " + remoteAddr + "\n";
        try {
            //InetAddress inet = InetAddress.getByName(remoteAddr);
            String inet = HostUtil.reverseLookup(remoteAddr);
            if (inet != null) {
                //er += "Rev DNS: " + inet.getHostName() + "\n";
                er += "Rev DNS: " + inet + "\n";
            }else{
                er += "Rev DNS: (unknown)\n";
            }
        } catch (Exception e) {
        }
        er += "Servlet: " + ed.getServletName() + "\n";
        er += "URL    : " + ed.getRequestURI() + "\n";
        er += "\n";

        if (exception != null) {
            er += "Exception\n";
            er += "---------\n";
            er += exception.toString() + "\n";
            StackTraceElement[] st = exception.getStackTrace();
            for (int i = 0; i < st.length; i++) {
                er += "    " + st[i].toString() + "\n";
            }
            er += "\n";

            Throwable cause = exception.getCause();
            if (cause != null) {
                er += "Root Cause\n";
                er += "----------\n";
                er += cause.toString() + "\n";
                st = cause.getStackTrace();
                for (int i = 0; i < st.length; i++) {
                    er += "    " + st[i].toString() + "\n";
                }
                er += "\n";
            }
        }

        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            er += "Cookies\n";
            er += "-------\n";
            for (int i = 0; i < cookies.length; i++) {
                er += cookies[i].getName() +" : "+ cookies[i].getValue() + "\n";
            }
            er += "\n";
        }

        sendEmail(er,request.getServerName());

        out.println("<pre>");
        out.println(er);
        out.println("The error has been reported to system administrators.");
        out.println("</pre>");
    } else {
        out.println("<p>No information about this error was available.</p>");
    }
%>

</body>
</html>
