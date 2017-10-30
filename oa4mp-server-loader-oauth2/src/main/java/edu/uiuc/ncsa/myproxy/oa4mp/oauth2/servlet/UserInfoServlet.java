package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.security.core.exceptions.InvalidTimestampException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.delegation.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;
import edu.uiuc.ncsa.security.oauth_2_0.server.ScopeHandler;
import edu.uiuc.ncsa.security.oauth_2_0.server.UII2;
import edu.uiuc.ncsa.security.oauth_2_0.server.UIIRequest2;
import edu.uiuc.ncsa.security.oauth_2_0.server.UIIResponse2;
import org.apache.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.LinkedList;

import static edu.uiuc.ncsa.security.core.util.DateUtils.checkTimestamp;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/4/13 at  11:09 AM
 */
public class UserInfoServlet extends MyProxyDelegationServlet {
    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        // The access token is sent in the authorization header and should look like
        // Bearer oa4mp:...

        AccessToken at = getAT(request);
        ServiceTransaction transaction = (ServiceTransaction) getTransactionStore().get(at);
        if (((OA2Client) transaction.getClient()).isPublicClient()) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "public client not authorized to access user information", HttpStatus.SC_UNAUTHORIZED);
        }
        if (transaction == null) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "no transaction for the access token was found.", HttpStatus.SC_BAD_REQUEST);
        }
        if (!transaction.isAccessTokenValid()) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "invalid access token.", HttpStatus.SC_BAD_REQUEST);
        }
        try {
            checkTimestamp(at.getToken());
        } catch (InvalidTimestampException itx) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "token expired.", HttpStatus.SC_BAD_REQUEST);
        }
        OA2SE oa2SE = (OA2SE)getServiceEnvironment();
        UII2 uis = new UII2(oa2SE.getTokenForge(), getServiceEnvironment().getServiceAddress());
        UIIRequest2 uireq = new UIIRequest2(request, at);
        uireq.setUsername(getUsername(transaction));
        // Now we figure out which scope handler to use.
        UIIResponse2 uiresp = (UIIResponse2) uis.process(uireq);
        LinkedList<ScopeHandler> scopeHandlers = OA2ATServlet.setupScopeHandlers((OA2ServiceTransaction) transaction, oa2SE);
        DebugUtil.dbg(this, "Invoking scope handler");
        if (scopeHandlers == null || scopeHandlers.isEmpty()) {
            DebugUtil.dbg(this, " ***** NO SCOPE HANDLERS ");

        }
        for (ScopeHandler scopeHandler : scopeHandlers) {
            DebugUtil.dbg(this, " scope handler=" + scopeHandler.getClass().getSimpleName());

            scopeHandler.process(uiresp.getUserInfo(), transaction);
        }
        uiresp.write(response);
    }

    /**
     * Override this if needed.
     *
     * @param transaction
     * @return
     */
    protected String getUsername(ServiceTransaction transaction) {
        return transaction.getUsername();
    }

    // not implemented.
    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
        return null;
    }
    protected String getRawAT(HttpServletRequest request){
        String rawAT = null;
             String headerAT = HeaderUtils.getBearerAuthHeader(request);
             String paramAT = getFirstParameterValue(request, OA2Constants.ACCESS_TOKEN);

             if (paramAT == null) {
                 if (headerAT == null) {
                     throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "no access token was sent.", HttpStatus.SC_BAD_REQUEST);
                 }
                 rawAT = headerAT;
             } else {
                 if (headerAT == null) {
                     rawAT = paramAT;
                 } else {
                     if (!paramAT.equals(headerAT)) {
                         throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "too many access tokens.", HttpStatus.SC_BAD_REQUEST);
                     }
                     rawAT = paramAT;
                 }
             }
        return rawAT;
    }
    protected AccessToken getAT(HttpServletRequest request) {
        return new AccessTokenImpl(URI.create(getRawAT(request)), null);
    }
}
