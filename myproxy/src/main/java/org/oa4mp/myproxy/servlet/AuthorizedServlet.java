package org.oa4mp.myproxy.servlet;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.DateUtils;
import org.apache.http.HttpStatus;
import org.oa4mp.delegation.common.token.AuthorizationGrant;
import org.oa4mp.delegation.server.ServiceTransaction;
import org.oa4mp.server.api.storage.servlet.OA4MPServlet;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;

/**
 * For deployment in cases that there is a wholly external authorization webapp.
 * That webapp makes a call to this servlet following a specific mini-protocol
 * and the response from this servlet contains the redirect url which must then
 * cause a redirect in the user's browser.
 * <p>Created by Jeff Gaynor<blifetr>
 * on 2/13/14 at  3:24 PM
 */
public abstract class AuthorizedServlet extends MyProxyServlet {
    public static final String STATUS_KEY = "status";
    public static final String STATUS_OK = "ok";
    public static final String REDIRECT_URL_KEY = "redirect_url";

    public abstract String createCallback(ServiceTransaction transaction);

    public static class ProtocolParameters {
        public String token;
        public String loa;
        public String userId;
        public long lifetime;
        public String password;
    }

    /**
     * This will take the HTTP request and parse it into parameters. This method is the one to override
     * if you have tweaks to the basic protocol.
     *
     * @param request
     * @return
     */
abstract    protected ProtocolParameters parseRequest(HttpServletRequest request) throws ServletException;

    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        /**
         * For the case that this is being used strictly as a back channel for authorized users.
         * This will process the request and return a standard response that includes the redirect
         * url. Applications calling this must parse the response and use it as per the spec.,  sending
         * it as a redirect to the user's browser.
         * @param request
         * @param response
         * @throws Throwable
         */
        ProtocolParameters p = parseRequest(request);
        ServiceTransaction trans = getAndCheckTransaction(p);
        trans.setUsername(p.userId);
        getTransactionStore().save(trans); // keep the user name
        createMPConnection(trans.getIdentifier(), p.userId, p.password, p.lifetime);
        doRealCertRequest(trans, "");
        writeResponse(response, trans);
    }

    /**
     * Write the response to the output stream and returns the callback that was generated, if there is one.
     * @param response
     * @param transaction
     * @return
     * @throws IOException
     */
    protected void writeResponse(HttpServletResponse response, ServiceTransaction transaction) throws IOException {
        String cb = createCallback(transaction);

        Writer w = response.getWriter();
        String returnedString = STATUS_KEY + "=" + STATUS_OK + "\n";
        response.setStatus(HttpStatus.SC_OK);
        returnedString = returnedString + REDIRECT_URL_KEY + "=" + cb;
        w.write(returnedString);
        w.close();
        response.sendRedirect(cb);
    }

    /*
   Get the transaction associated with the authorization grant token and check that it passes sanity
   checks. If so, return it, If not, throw the appropriate exception.
*/
    protected ServiceTransaction getAndCheckTransaction(ProtocolParameters p) throws Throwable {
        String token = p.token;
        DateUtils.checkTimestamp(token);
        AuthorizationGrant grant = OA4MPServlet.getServiceEnvironment().getTokenForge().getAuthorizationGrant(token);
        DateUtils.checkTimestamp(grant.getToken());
        ServiceTransaction trans = OA4MPServlet.getServiceEnvironment().getTransactionStore().get(grant);
        if (trans == null) {
            warn("Error: no delegation request found for " + token);
            throw new GeneralException("Error: no delegation request found.");
        }
        checkClientApproval(trans.getClient());
        return trans;
    }

}
