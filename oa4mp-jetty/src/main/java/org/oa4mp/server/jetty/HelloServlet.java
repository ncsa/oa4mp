package org.oa4mp.server.jetty;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
/*
Dummy servlet for testing. It gets created to show that starting a servlet
works, but really does almost nothing.
 */
public class HelloServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        resp.setContentType("text/html");
        resp.setStatus(HttpServletResponse.SC_OK);
        resp.getWriter().println("<h1>Hello from Embedded Jetty!</h1>");
        System.out.println("Hello from Embedded Jetty!");
    }
}
