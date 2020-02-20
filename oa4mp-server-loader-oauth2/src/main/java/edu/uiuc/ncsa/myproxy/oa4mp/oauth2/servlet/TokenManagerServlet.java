package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.RefreshTokenStore;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;
import edu.uiuc.ncsa.security.oauth_2_0.OA2TokenForge;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import net.sf.json.JSONObject;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.HttpStatus;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

/**
 * Superclass for {@link RFC7009} and{@link RFC7662} plus perhaps any others.
 * <p>Created by Jeff Gaynor<br>
 * on 2/17/20 at  2:21 PM
 */
public abstract class TokenManagerServlet extends MyProxyDelegationServlet {
    public static String TOKEN = "token";
    public static String TOKEN_TYPE_HINT = "token_type_hint";
    public static String TYPE_ACCESS_TOKEN = "access_token";
    public static String TYPE_REFRESH_TOKEN = "refresh_token";

    protected OA2Client verifyClient(HttpServletRequest req, String headerAuthz) throws UnsupportedEncodingException {
        OA2SE oa2SE = (OA2SE) getServiceEnvironment().getTransactionStore();
        String[] credentials = HeaderUtils.getCredentialsFromHeaders(req, headerAuthz);
        // need to verify that this is an admin client.
        Identifier acID = BasicIdentifier.newID(credentials[HeaderUtils.ID_INDEX]);
        if (!oa2SE.getClientStore().containsKey(acID)) {
            throw new GeneralException("Error: the given id of \"" + acID + "\" is not recognized as valid client.");
        }
        String adminSecret = credentials[HeaderUtils.SECRET_INDEX];
        if (adminSecret == null || adminSecret.isEmpty()) {
            throw new GeneralException("Error: missing secret.");
        }
        OA2Client client = (OA2Client) oa2SE.getClientStore().get(acID);
        if (!oa2SE.getClientApprovalStore().isApproved(acID)) {
            ServletDebugUtil.trace(this, "Client \"" + acID + "\" is not approved.");
            throw new GeneralException("error: This  client has not been approved.");
        }
        String hashedSecret = DigestUtils.sha1Hex(adminSecret);
        if (!client.getSecret().equals(hashedSecret)) {
            throw new GeneralException("error: client and secret do not match");
        }
        return client;
    }

    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
        return null;
    }

    @Override
    public void doGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {
        httpServletResponse.setStatus(HttpStatus.SC_SERVICE_UNAVAILABLE);
        throw new ServletException("Unsupported operation");
    }

    protected int getTokenType(String token) {
        OA2SE oa2SE = (OA2SE) getServiceEnvironment();
        return ((OA2TokenForge) oa2SE.getTokenForge()).getType(token);
    }

    protected void writeOK(HttpServletResponse httpServletResponse, JSONObject resp) throws IOException {
        httpServletResponse.setContentType("application/json");
        httpServletResponse.getWriter().println(resp.toString());
        httpServletResponse.getWriter().flush(); // commit it
        httpServletResponse.setStatus(HttpStatus.SC_OK);
    }

    protected OA2ServiceTransaction getTransFromToken(String token) {
        OA2SE oa2SE = (OA2SE) getServiceEnvironment().getTransactionStore();
        OA2TokenForge tf = (OA2TokenForge) oa2SE.getTokenForge();
        switch (tf.getType(token)) {
            case OA2TokenForge.TYPE_AUTH_GRANT:
                throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "invalid request", HttpStatus.SC_BAD_REQUEST);
    /*      This is the code to handle Authorization grant revocations if we ever want to do that too...
                case OA2TokenForge.TYPE_AUTH_GRANT:
                    t = oa2SE.getTransactionStore().get(tf.getAuthorizationGrant(token));
                    break;
    */
            case OA2TokenForge.TYPE_ACCESS_TOKEN:
                return (OA2ServiceTransaction) oa2SE.getTransactionStore().get(tf.getAccessToken(token));
            case OA2TokenForge.TYPE_REFRESH_TOKEN:
                RefreshTokenStore refreshTokenStore = (RefreshTokenStore) oa2SE.getTransactionStore();
                return refreshTokenStore.get(tf.getRefreshToken(token));
        }
        return null;
    }
}
