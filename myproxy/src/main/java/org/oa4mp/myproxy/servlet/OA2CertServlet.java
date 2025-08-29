package org.oa4mp.myproxy.servlet;

import edu.uiuc.ncsa.myproxy.MPSingleConnectionProvider;
import edu.uiuc.ncsa.security.core.exceptions.InvalidTimestampException;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import net.sf.json.JSONObject;
import org.apache.http.HttpStatus;
import org.oa4mp.delegation.common.servlet.TransactionState;
import org.oa4mp.delegation.common.token.AccessToken;
import org.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import org.oa4mp.delegation.common.token.impl.TokenUtils;
import org.oa4mp.delegation.server.*;
import org.oa4mp.delegation.server.jwt.MyOtherJWTUtil2;
import org.oa4mp.delegation.server.request.IssuerResponse;
import org.oa4mp.delegation.server.server.PAIResponse2;
import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.servlet.OA2HeaderUtils;
import org.oa4mp.server.loader.oauth2.storage.transactions.OA2ServiceTransaction;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.List;

import static edu.uiuc.ncsa.security.core.util.DateUtils.checkTimestamp;
import static org.oa4mp.delegation.server.server.claims.OA2Claims.JWT_ID;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/20/14 at  12:50 PM
 */
public class OA2CertServlet extends ACS2 {
    @Override
    protected AccessToken getAccessToken(HttpServletRequest request) {
        String rawAT = request.getParameter(OA2Constants.ACCESS_TOKEN);
        if (rawAT == null) {
            // this just means that the access token was not sent as a parameter. It
            // might have been sent as a bearer token.
            List<String> bearerTokens = OA2HeaderUtils.getAuthHeader(request, "Bearer");
            if (bearerTokens.isEmpty()) {
                throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                        "missing access token",
                        HttpStatus.SC_BAD_REQUEST,
                        null);
            }
            if (1 < bearerTokens.size()) {
                throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                        "too many access tokens",
                        HttpStatus.SC_BAD_REQUEST,
                        null);
            }
            rawAT = bearerTokens.get(0);
        }
        // If there is nothing in the raw access token at this point, then nothing was sent.

        if (StringUtils.isTrivial(rawAT)) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                    "missing access token",
                    HttpStatus.SC_BAD_REQUEST,
                    null);
        }
        // Now decide if it's a JWT

        try {
            OA2SE oa2se = (OA2SE) getServiceEnvironment();

            JSONObject jwt = MyOtherJWTUtil2.verifyAndReadJWT(rawAT, oa2se.getJsonWebKeys());
            if (jwt.containsKey(JWT_ID)) {
                rawAT = jwt.getString(JWT_ID);
            } else {
                throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                        "The access token is a JWT, but does not have a \" + JWT_ID + \" claim and cannot be processed.",
                        HttpStatus.SC_BAD_REQUEST,
                        null);

            }
        } catch (Throwable t) {
            if (TokenUtils.isBase32(rawAT)) {
                rawAT = TokenUtils.b32DecodeToken(rawAT);
            }
            // It is a standard access token, not a jwt.
        }

        return new AccessTokenImpl(URI.create(rawAT));
    }

    /**
     * This looks for the information about the client and checks the secret.
     *
     * @return
     */
    /*
       NOTE: NOT SURE IF NEXT METHOD NEEDED!! Adding JGlobus to the dependencies in the module
             causes a compilation error at line 144 executing

             DigestUtils.sha1Hex(rawSecret

             since there is a DigestUtils in the JGlobus API. I *think* this method is
             probably redundant, but am not 100% sure until I can test against a MyProxy server
             Keeping block in case it needs work.


     */
 /*   @Override
    public Client getClient(HttpServletRequest req) {
        String rawID = req.getParameter(CONST(CONSUMER_KEY));
        String rawSecret = getFirstParameterValue(req, CLIENT_SECRET);
        // According to the spec. this must be in a Basic Authz header if it is not sent as parameter

        if (rawID == null) {
            // maybe it was sent as an authorization header
            // now we have to check for which of these is the identifier

            // https://github.com/rcauth-eu/OA4MP/commit/9227794f8c8589087c3460ae0918e4f7443f5bc8
            try {
                String[] basicTokens = HeaderUtils.getCredentialsFromHeaders(req);
                rawID = basicTokens[HeaderUtils.ID_INDEX];
                rawSecret = basicTokens[HeaderUtils.SECRET_INDEX];
            } catch (UnsupportedEncodingException e) {
                // Note: we don't catch other exceptions: they can be thrown directly
                throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                        "Could not parse the Basic authorization header for client ID/secret.",
                        HttpStatus.SC_BAD_REQUEST,null);
            }
        }
        if (rawID == null) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                    "No client id",
                    HttpStatus.SC_BAD_REQUEST,
                    null
            );
        }
        Identifier id = BasicIdentifier.newID(rawID);
        OA2Client client = (OA2Client) getClient(id);
        if (client.isPublicClient()) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                    "public clients not supported for this operation",
                    HttpStatus.SC_BAD_REQUEST,
                    null, client
            );
        }
        if (rawSecret == null) {
            throw new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT,
                    "no secret, request refused.",
                    HttpStatus.SC_UNAUTHORIZED,
                    null, client
            );
        }
        if (!client.getSecret().equals(DigestUtils.sha1Hex(rawSecret))) {
            throw new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT,
                    "incorrect secret, request refused.",
                    HttpStatus.SC_UNAUTHORIZED,
                    null, client
            );
        }
        return client;
    }
*/
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
        PAIResponse2 par = (PAIResponse2) iResponse;
        AccessToken accessToken = par.getAccessToken();
        OA2ServiceTransaction t = (OA2ServiceTransaction) getTransactionStore().get(accessToken);
        // CIL-404 fix. Throw appropriate exceptions. Do not use the callback mechanism from OAuth for errors since that returns
        // an HTTP status code of 200 with no other information.
        if (t == null) {
            throw new OA2GeneralError(OA2Errors.INVALID_TOKEN,
                    "Invalid access token",
                    HttpStatus.SC_BAD_REQUEST,
                    null);
        }
        if (!t.getScopes().contains(OA2Scopes.SCOPE_MYPROXY)) {
            // Note that this requires a state, but none is sent in the OA4MP cert request.
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                    "Certificate request is not in scope.",
                    HttpStatus.SC_BAD_REQUEST,
                    t.getRequestState(),
                    t.getClient());
        }


        if (!t.isAccessTokenValid()) {
            throw new OA2GeneralError(OA2Errors.INVALID_TOKEN,
                    "invalid token",
                    HttpStatus.SC_BAD_REQUEST,
                    t.getRequestState(),
                    t.getClient()
            );

        }
        checkClientApproval(t.getClient());
        // Access tokens must be valid in order to get a cert. If the token is invalid, the user must
        // get a valid one using the refresh token.
        try {
            checkTimestamp(accessToken.getToken());
        }catch(InvalidTimestampException invalidTimestampException){
            throw new OA2GeneralError(OA2Errors.INVALID_TOKEN,
                    "expired token",
                    HttpStatus.SC_BAD_REQUEST,
                    t.getRequestState(), t.getClient()
            );

        }
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
        OA2ServiceTransaction st = (OA2ServiceTransaction) trans;


        if (!st.getFlowStates().acceptRequests || !st.getFlowStates().getCert) {
            throw new OA2GeneralError(OA2Errors.ACCESS_DENIED,
                    "access denied",
                    HttpStatus.SC_UNAUTHORIZED,
                    st.getRequestState(), st.getClient());
        }
        OA2SE oa2SE = (OA2SE) getServiceEnvironment();

        if (!oa2SE.isTwoFactorSupportEnabled()) {
            checkMPConnection(st);
        } else {
            // The assumption at this point is that the connection information has been stashed, but has not been
            // used since the password is valid exactly once. Here is where we set up the connection once
            // and for all.
            if (!getMyproxyConnectionCache().containsKey(st.getIdentifier())) {
                throw new OA2GeneralError(OA2Errors.SERVER_ERROR,
                        "No cached my proxy object with identifier " + st.getIdentifierString(),
                        HttpStatus.SC_SERVICE_UNAVAILABLE,
                        st.getRequestState(), st.getClient());
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
