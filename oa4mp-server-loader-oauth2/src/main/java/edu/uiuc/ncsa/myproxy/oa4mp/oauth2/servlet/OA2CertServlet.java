package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.MPSingleConnectionProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.ACS2;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractAuthorizationServlet.MyMyProxyLogon;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.delegation.servlet.TransactionState;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Scopes;
import edu.uiuc.ncsa.security.oauth_2_0.server.PAIResponse2;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.List;

import static edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceConstantKeys.CONSUMER_KEY;
import static edu.uiuc.ncsa.security.core.util.DateUtils.checkTimestamp;
import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.CLIENT_SECRET;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/20/14 at  12:50 PM
 */
public class OA2CertServlet extends ACS2 {
    @Override
    protected AccessToken getAccessToken(HttpServletRequest request) {
        try {
            return getServiceEnvironment().getTokenForge().getAccessToken(request);
        } catch (Throwable t) {
            // this just means that the access token was not sent as a parameter. It
            // might have been sent as a bearer token.
        }
        List<String> bearerTokens = getAuthHeader(request, "Bearer");
        if (bearerTokens.isEmpty()) {
            throw new GeneralException("Error: no access token");
        }
        if (1 < bearerTokens.size()) {
            throw new GeneralException("Error: too many access tokens");
        }
        AccessToken at = getServiceEnvironment().getTokenForge().getAccessToken(bearerTokens.get(0));

        return at;
    }

    /**
     * This looks for the information about the client and checks the secret.
     *
     * @param req
     * @return
     */
    @Override
    public Client getClient(HttpServletRequest req) {
        String rawID = req.getParameter(CONST(CONSUMER_KEY));
        String rawSecret = getFirstParameterValue(req, CLIENT_SECRET);
        // According to the spec. this must be in anBasic Authz header if it is not sent as parameter
        List<String> basicTokens = getAuthHeader(req, "Basic");
        if (2 < basicTokens.size()) {
            // too many tokens to unscramble
            throw new OA2GeneralError(OA2Errors.INVALID_TOKEN, "Error: Too many authorization tokens.", HttpStatus.SC_UNAUTHORIZED);
            //throw new GeneralException("Too many authorization tokens");
        }
        if (rawID == null) {
            // maybe it was sent as an authorization header
            // now we have to check for which of these is the identifier

            for (String x : basicTokens) {
                try {
                    // Here is some detective work. We get up to TWO basic Authz headers with the id and secret.
                    // Since ids are valid URIs the idea here is anything that is uri must be an id and the other
                    // one is the secret. This also handles the case that one of these is sent as a parameter
                    // in the call and the other is in the header.
                    URI test = URI.create(x);
                    // It is possible that the secret may be parseable as a valid URI (plain strings are
                    // trivially uris). This checks that there a
                    // scheme, which implies this is an id. The other token is assumed to
                    // be the secret.
                    if (test.getScheme() != null) {
                        rawID = x;
                    } else {
                        rawSecret = x;
                    }
                } catch (Throwable t) {
                    if (rawSecret == null) {
                        rawSecret = x;
                    }
                }
            }
        }
        if (rawID == null) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "Error: No client id.", HttpStatus.SC_BAD_REQUEST);

            //throw new UnknownClientException("No client id");
        }
        Identifier id = BasicIdentifier.newID(rawID);
        OA2Client client = (OA2Client) getClient(id);

        if (rawSecret == null) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                    "Error: No secret. request refused.",
                    HttpStatus.SC_BAD_REQUEST);
        }
        if (!client.getSecret().equals(DigestUtils.shaHex(rawSecret))) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                    "Error: Secret is incorrect. request refused.",
                    HttpStatus.SC_BAD_REQUEST);

        }
        return client;
    }

    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
        PAIResponse2 par = (PAIResponse2) iResponse;
        AccessToken accessToken = par.getAccessToken();
        OA2ServiceTransaction t = (OA2ServiceTransaction) getTransactionStore().get(accessToken);
    /*    if (t == null) {
            throw new OA2GeneralError(OA2Errors.INVALID_TOKEN, "Invalid access token. Request refused", HttpStatus.SC_UNAUTHORIZED);
        }
        if (!t.getScopes().contains(OA2Scopes.SCOPE_MYPROXY)) {
            // Note that this requires a state, but none is sent in the OA4MP cert request.
            throw new OA2GeneralError(OA2Errors.INVALID_SCOPE, "Certificate request is not in scope.", HttpStatus.SC_FORBIDDEN);
        }
        if (t == null) {
            throw new OA2GeneralError(OA2Errors.INVALID_TOKEN, "No transaction found for access token \"" + accessToken + "\"", HttpStatus.SC_UNAUTHORIZED);
        }

        if (!t.isAccessTokenValid()) {
            throw new OA2GeneralError(OA2Errors.INVALID_TOKEN, "Invalid access token. Request refused", HttpStatus.SC_UNAUTHORIZED);
        }*/
        // CIL-404 fix. Throw appropriate exceptions. Do not use the callback mechanism from OAuth for errors since that returns
        // an HTTP status code of 200 with no other information.
        if (t == null) {
            throw new GeneralException("Invalid access token. Request refused");
        }
        if (!t.getScopes().contains(OA2Scopes.SCOPE_MYPROXY)) {
            // Note that this requires a state, but none is sent in the OA4MP cert request.
            throw new GeneralException("Certificate request is not in scope.");
        }
        if (t == null) {
            throw new GeneralException("No transaction found for access token \"" + accessToken + "\"");
        }

        if (!t.isAccessTokenValid()) {
            throw new GeneralException("Invalid access token. Request refused");
        }
        checkClient(t.getClient());
        // Access tokens must be valid in order to get a cert. If the token is invalid, the user must
        // get a valid one using the refresh token.
        checkTimestamp(accessToken.getToken());
        return t;
    }

    protected void checkMPConnection(OA2ServiceTransaction st) throws GeneralSecurityException {
        if (!hasMPConnection(st)) {
            createMPConnection(st.getIdentifier(), st.getMyproxyUsername(), "", st.getLifetime());
        }
    }

    @Override
    protected void doRealCertRequest(ServiceTransaction trans, String statusString) throws Throwable {
        // CIL-243: binding the CR's DN to the user name. Uncomment if we ever decide to do this         \
/*
        if (trans.getCertReq().getCN()==null || (!trans.getUsername().equals(trans.getCertReq().getCN()))) { // CN can be null
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "The common name on the cert request is \"" +
                    trans.getCertReq().getCN() +
                    "\" which does not match the username \"" + trans.getUsername() + "\"", HttpStatus.SC_BAD_REQUEST);
        }
*/
        OA2ServiceTransaction st = (OA2ServiceTransaction) trans;
        OA2SE oa2SE = (OA2SE) getServiceEnvironment();
        if (!oa2SE.isTwoFactorSupportEnabled()) {
            checkMPConnection(st);
        } else {
            // The assumption at this point is that the connection information has been stashed, but has not been
            // used since the password is valid exactly once. Here is where we set up the connection once
            // and for all.
            if (!getMyproxyConnectionCache().containsKey(st.getIdentifier())) {
                throw new GeneralException("No cached my proxy object with identifier " + st.getIdentifierString());
            }
            MPSingleConnectionProvider.MyProxyLogonConnection mpc = (MPSingleConnectionProvider.MyProxyLogonConnection) getMyproxyConnectionCache().get(st.getIdentifier()).getValue();
            // First pass will be a MyMyProxyLogon object that allows completing the logon.
            // After that it will be a regular MyProxyLogon object. Since the password is valid for
            // a very short period (typically only up to a minute or two), the logon can fail if
            // not done promptly by the user.
            if (mpc.getMyProxyLogon() instanceof MyMyProxyLogon) {
                MyMyProxyLogon myProxyLogon = (MyMyProxyLogon) mpc.getMyProxyLogon();
                getMyproxyConnectionCache().remove(mpc.getIdentifier());
                createMPConnection(trans.getIdentifier(), myProxyLogon.getUsername(), myProxyLogon.getPassphrase(), trans.getLifetime());
            }
        }
        doCertRequest(st, statusString);
    }

    @Override
    public void postprocess(TransactionState state) throws Throwable {
        super.postprocess(state);
        OA2ServiceTransaction t = (OA2ServiceTransaction) state.getTransaction();
        if (((OA2SE) getServiceEnvironment()).isRefreshTokenEnabled() && t.hasRefreshToken()) {
            // If this has a refresh token, then then do not invalidate the access token, since
            // users may re-get certs for the lifetime of the refresh token.
            t.setAccessTokenValid(true);
            getTransactionStore().save(t);
        }
    }
}
