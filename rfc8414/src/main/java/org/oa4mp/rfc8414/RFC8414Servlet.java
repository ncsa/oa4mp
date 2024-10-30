package org.oa4mp.rfc8414;

import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * A servlet to fulfill <a href="https://datatracker.ietf.org/doc/html/rfc8414">RFC 8414</a>,
 * discovery for OAuth servers. Since Tomcat does not have a good mechanism for this, a basic servlet
 * that forwards everything to the OA4MP instance's Discovery servlet is used. Only deploy this in a pure
 * Tomcat environment, not if, e.g., Tomcat is fronted by Apache. In that case, you should use
 * mod_rewrite to get the .well-known page. The reason we forward is that the state etc. needed for
 * this is quite extensive and really cannot be replicated outside of OA4MP itself, so just ask.
 */
// Fixes https://github.com/ncsa/oa4mp/issues/175
public class RFC8414Servlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        ServletDebugUtil.printAllParameters(getClass(), req, true);
        resp.sendRedirect("/oauth2" + req.getRequestURI());
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        doGet(req, resp);
    }

    @Override
    protected void doPut(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        throw new UnsupportedOperationException("Not supported.");
    }

    @Override
    protected void doDelete(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        throw new UnsupportedOperationException("Not supported.");
    }
}
