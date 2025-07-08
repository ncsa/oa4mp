package org.oa4mp.server.loader.oauth2.servlet;

import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.storage.transactions.OA2ServiceTransaction;
import org.oa4mp.server.loader.oauth2.claims.IDTokenHandler;
import org.oa4mp.server.loader.oauth2.claims.PayloadHandlerConfigImpl;
import org.oa4mp.server.loader.oauth2.state.ScriptRuntimeEngineFactory;
import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.loader.oauth2.tokens.UITokenUtils;
import org.oa4mp.delegation.server.*;
import org.qdl_lang.exceptions.AssertionException;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import org.oa4mp.delegation.server.ServiceTransaction;
import org.oa4mp.delegation.server.request.IssuerResponse;
import org.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import org.oa4mp.delegation.server.jwt.HandlerRunner;
import org.oa4mp.delegation.server.jwt.ScriptRuntimeException;
import org.oa4mp.delegation.server.server.UII2;
import org.oa4mp.delegation.server.server.UIIRequest2;
import org.oa4mp.delegation.server.server.UIIResponse2;
import edu.uiuc.ncsa.security.servlet.AbstractServlet;
import net.sf.json.JSONObject;
import org.apache.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.oa4mp.server.loader.oauth2.tokens.UITokenUtils.getRawAT;
import static org.oa4mp.delegation.server.OA2Constants.*;
import static org.oa4mp.delegation.server.server.claims.OA2Claims.EXPIRATION;
import static org.oa4mp.delegation.server.server.claims.OA2Claims.ISSUED_AT;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/4/13 at  11:09 AM
 */
public class UserInfoServlet extends BearerTokenServlet {
    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        // The access token is sent in the authorization header and should look like
        // Bearer oa4mp:...
        AccessTokenImpl at = null;
        try {
             at = UITokenUtils.getAT(getRawAT(request));
        }catch(Throwable t){
            // CIL-1638 as per spec if complete garbage is given for the AT, add header and set status
            // This blows up before there is any change to start handling the error in another way.
            response.setHeader("WWW-Authenticate", "Bearer realm=\"oa4mp\", error=\"invalid_token\"");
            response.setStatus(HttpStatus.SC_UNAUTHORIZED);
            return;
        }
        TokenManagerServlet.State state = new TokenManagerServlet.State();
        OA2ServiceTransaction transaction = null;
        try {
            transaction = findTransaction(at, state);
        }catch(OA2GeneralError e){
            e.setForensicMessage(e.getForensicMessage() + "\nerror in user info endpoint.");
            throw e;
        }
        // Fix for CIL-1124
        if(!transaction.isAccessTokenValid()){
            // CIL-1638, https://www.rfc-editor.org/rfc/rfc6750 Errors relating to the bearer token require this header.
            response.setHeader("WWW-Authenticate", "Bearer realm=\"oa4mp\", error=\"invalid_token\"");

            throw new OA2RedirectableError(OA2Errors.ACCESS_DENIED,
                     "access denied", HttpStatus.SC_UNAUTHORIZED,
                     transaction.getRequestState(),
                     transaction.getCallback());
        }
        // CIL-1104 fix. Only give back user info if the original request asked for openid
        // We do not do this for subsequent requests because, since this is private information,
        // the user must consent to it, so this scope *has* to be in the initial request.
        if(!transaction.getScopes().contains(OA2Scopes.SCOPE_OPENID)){
            throw new OA2RedirectableError(OA2Errors.ACCESS_DENIED,
                     "access denied", HttpStatus.SC_UNAUTHORIZED,
                     transaction.getRequestState(),
                     transaction.getCallback());
        }
        OA2SE oa2SE = (OA2SE) getServiceEnvironment();
        MetaDebugUtil debugger = createDebugger(transaction.getOA2Client());
        if (!transaction.getFlowStates().userInfo) {
            throw new OA2RedirectableError(OA2Errors.ACCESS_DENIED,
                    "access denied", HttpStatus.SC_UNAUTHORIZED,
                    transaction.getRequestState(),
                    transaction.getCallback());
        }
        checkAdminClientStatus(transaction.getClient().getIdentifier());
        // if we get to here, then the access token checked out, so we can just get it and use it.

        // Need to look this up by its jti if its not a basic access token.
        OA2Client resolvedClient = OA2ClientUtils.resolvePrototypes(oa2SE, transaction.getOA2Client());

        UII2 uis = new UII2(oa2SE.getTokenForge(), getServiceEnvironment().getServiceAddress());
        UIIRequest2 uireq = new UIIRequest2(request, at);
        uireq.setUsername(getUsername(transaction));
        UIIResponse2 uiresp = (UIIResponse2) uis.process(uireq);
        // creates the token handler just to get the updated accounting information.
        IDTokenHandler idTokenHandler = new IDTokenHandler(new PayloadHandlerConfigImpl(
                resolvedClient.getIDTokenConfig(),
                oa2SE,
                transaction,
                resolvedClient,
                null, // no token exchange record outside of token exchanges.
                null));
        idTokenHandler.refreshAccountingInformation();

        HandlerRunner handlerRunner = new HandlerRunner(transaction, ScriptRuntimeEngineFactory.createRTE(oa2SE, transaction, null, resolvedClient.getConfig()));
        OA2ClientUtils.setupHandlers(handlerRunner, oa2SE, transaction, resolvedClient, request);
        try {
            handlerRunner.doUserInfo();
        } catch (AssertionException assertionError) {
            debugger.trace(this, "assertion exception \"" + assertionError.getMessage() + "\"");
            throw new OA2ATException(OA2Errors.INVALID_REQUEST,
                    assertionError.getMessage(),
                    HttpStatus.SC_BAD_REQUEST,
                    transaction.getRequestState(),
                    transaction.getClient());
        } catch (ScriptRuntimeException sre) {
            // Client threw an exception.
            debugger.trace(this, "script runtime exception \"" + sre.getMessage() + "\"");
            throw new OA2ATException(sre.getRequestedType(), sre.getMessage(), sre.getHttpStatus(), transaction.getRequestState(),
                    transaction.getClient());
        } catch (IllegalAccessException iax) {
            throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT,
                    "access denied",
                    transaction.getRequestState(),
                    transaction.getClient());
        } catch (Throwable throwable) {
            debugger.trace(this, "Unable to update claims on token refresh", throwable);
            debugger.warn(this, "Unable to update claims on token refresh: \"" + throwable.getMessage() + "\"");
        }
        //setupTokens(client, rtiResponse, oa2SE, t, jwtRunner);
        debugger.trace(this, "finished processing claims.");

        if (handlerRunner.hasATHandler()) {
            transaction.setUserMetaData(handlerRunner.getAccessTokenHandler().getUserMetaData());
        } else {
            if (handlerRunner.hasIDTokenHandler()) {
                transaction.setUserMetaData(handlerRunner.getIdTokenHandlerInterface().getUserMetaData());
            }
        }

        getTransactionStore().save(transaction);
        uiresp.getUserInfo().getMap().putAll(stripClaims(transaction.getUserMetaData()));
        uiresp.write(response);
        info(getClass().getSimpleName() + ":request ok(" + AbstractServlet.getRequestIPAddress(request) + ")");

    }

    /**
     * This strips out claims that should not be returned, such as the nonce, but are part of the original
     * id token.
     *
     * @param json
     * @return
     */
    protected JSONObject stripClaims(JSONObject json) {
        JSONObject r = new JSONObject();
        r.putAll(json);// new json object so we don't lose information, and so we don't get concurrent update error
        // Request to strip issuer and audience as well https://github.com/rcauth-eu/OA4MP/commit/2c0ee22994de22d557fedd29203fdb9e6edb7a44
        // However, some installations require the issuer and audience to accept the token, so must keep.
        String[] x = new String[]{ISSUED_AT, NONCE, EXPIRATION, EXPIRES_IN, AUTHORIZATION_TIME};
        for (String y : x) {
            r.remove(y);
        }
        return r;
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


}
