package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.RefreshTokenStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;
import edu.uiuc.ncsa.security.delegation.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.security.delegation.token.impl.RefreshTokenImpl;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
// Todo - Have clients be able to access this somehow (they can get the uri in the configuration, but don't do anything with it)
// Todo -- add command line support for this so various tokens can be revoked at the command line. This require
//         a better concept of "revoked" Do we just remove the service transaction or do we allow for fine-tuning the
//         status of individual tokens? Probably for the first cut we do the former, since I think we will only want this
//         if there is a serious issue and we need to get rid of a user's state ASAP rather than being able to micromange it.

/**
 * Implements the <a href="https://tools.ietf.org/html/rfc7009">revocation specification</a>
 * <p>Note that according to this spec., revoking one of these implies revoking everything associated with
 * it so that a user may, in effect, performa alogout at some other service. This means in our case that we just remove the
 * transaction associated with the access token or the refresh token. If not token is found, that is considered a
 * benign condition.</p>
 * <p>Also note that there is no designated endpoint for this, so we can stick it anywhere. Generally I propose
 * <b>revoke/</b> as the endpoint for the service.</p>
 * <p>Created by Jeff Gaynor<br>
 * on 4/8/19 at  5:05 PM
 */
public class RevocationServlet extends MyProxyDelegationServlet {
    public static String REFRESH_TOKEN_HINT = "refresh_token";
    public static String ACCESS_TOKEN_HINT = "access_token";
    public static String TOKEN_TYPE_HINT = "token_type_hint";
    public static String REVOCATION_TOKEN = "token";

    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
        return null;
    }

    /**
     * There is exactly one error allowed in the spec for all failures. Here it is
     */
    protected void doError() {
        throw new OA2GeneralError("unsupported_token_type", "The authorization server does not support\n" +
                "           the revocation of the presented token type.  That is, the\n" +
                "           client tried to revoke an access token on a server not\n" +
                "           supporting this feature", HttpStatus.SC_INTERNAL_SERVER_ERROR);
        /* Note that it is also possible to return a status of 503 (HttpStatus.SC_SERVICE_UNAVAILABLE) which implies
           that for some reason the service cannot perform the request at this time, but that the token is still there
           and valid, so the request must be retried. In this case a "Retry-After" header in the response should
           be sent with a time of how long the service will be down. We do not do retries at this point, but note
           this is in the spec.
        */

    }

    protected void doOK(HttpServletResponse resp) {
        resp.setStatus(HttpStatus.SC_OK);
    }

    @Override
    protected void doIt(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable {
        if (!HeaderUtils.hasBasicHeader(httpServletRequest)) {
            throw new OA2GeneralError(OA2Errors.ACCESS_DENIED, "No basic header", HttpStatus.SC_UNAUTHORIZED);
        }
        String[] creds = HeaderUtils.getCredentialsFromHeaders(httpServletRequest, "Basic");
        Identifier id = BasicIdentifier.newID(creds[HeaderUtils.ID_INDEX]);
        if (!getServiceEnvironment().getClientStore().containsKey(id)) {
            throw new GeneralException("Error: unknown client.");
        }
        String rawSecret = creds[HeaderUtils.SECRET_INDEX];
        if (rawSecret == null || rawSecret.isEmpty()) {
            throw new GeneralException("Error: missing secret.");
        }
        String secret = DigestUtils.sha1Hex(rawSecret);
        Client client = getServiceEnvironment().getClientStore().get(id);
        if(!secret.equals(client.getSecret())){
            throw new GeneralException("Error: client and secret do not match");
        }

        String token = getFirstParameterValue(httpServletRequest, REVOCATION_TOKEN);
        if (token == null || token.isEmpty()) {
            doOK(httpServletResponse);
            return;
        }
        String tokenHint = getFirstParameterValue(httpServletRequest, TOKEN_TYPE_HINT);
        ServletDebugUtil.trace(this, "Got request to revoke token \"" + token + "\" with hint \"" + tokenHint + "\"");
        TransactionStore tStore = getServiceEnvironment().getTransactionStore();
        OA2ServiceTransaction transaction = null;
        // If the hint is sent that's nice, we basically ignore it as per the spec since all of our tokens
        // are typed.
        AccessToken at = new AccessTokenImpl(URI.create(token));
        transaction = (OA2ServiceTransaction) tStore.get(at);
        if (transaction == null) {
            RefreshToken refreshToken = new RefreshTokenImpl(URI.create(token));
            RefreshTokenStore rts = (RefreshTokenStore) tStore;

            transaction = rts.get(refreshToken);
        }
        if (transaction != null) {
            tStore.remove(transaction.getIdentifier());

        }
        doOK(httpServletResponse);
    }
}
