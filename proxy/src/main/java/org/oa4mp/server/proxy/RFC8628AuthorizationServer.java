package org.oa4mp.server.proxy;

import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.servlet.OA2ClientUtils;
import org.oa4mp.server.loader.oauth2.servlet.RFC8628Constants2;
import org.oa4mp.server.loader.oauth2.servlet.RFC8628State;
import org.oa4mp.server.loader.oauth2.state.ScriptRuntimeEngineFactory;
import org.oa4mp.server.loader.oauth2.storage.RFC8628Store;
import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.loader.oauth2.storage.transactions.OA2ServiceTransaction;
import org.oa4mp.server.api.storage.servlet.EnvServlet;
import org.oa4mp.server.api.storage.servlet.MyProxyDelegationServlet;
import org.oa4mp.server.api.storage.servlet.PresentationState;
import org.oa4mp.server.api.util.ClientDebugUtil;
import org.oa4mp.delegation.common.token.impl.AuthorizationGrantImpl;
import org.oa4mp.delegation.common.token.impl.TokenFactory;
import org.oa4mp.delegation.server.OA2ATException;
import org.oa4mp.delegation.server.OA2Errors;
import org.oa4mp.delegation.server.OA2GeneralError;
import org.oa4mp.delegation.server.jwt.JWTRunner;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.servlet.JSPUtil;
import edu.uiuc.ncsa.security.servlet.PresentableState;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.*;

import static org.oa4mp.server.api.ServiceConstantKeys.TOKEN_KEY;
import static org.oa4mp.server.api.storage.servlet.AbstractAuthorizationServlet.*;
import static org.oa4mp.server.proxy.OA2AuthorizationServer.scopesToString;
import static org.apache.commons.lang.StringEscapeUtils.escapeHtml;

/**
 * This does the authorization for the device flow.
 * <p>Created by Jeff Gaynor<br>
 * on 2/12/21 at  6:19 AM
 */
public class RFC8628AuthorizationServer extends EnvServlet {
    int DEFAULT_RETRY_COUNT = 3;

    public static final String USER_CODE_KEY = "AuthUserCode";

    protected String getInitialPage() {
        return "/" +
                "" +
                "" +
                "" +
                "" +
                "+---device-init.jsp";
    }

    protected String getRemoteUserInitialPage() {
        return "/device-remote-user.jsp";
    }

    protected String getOkPage() {
        return "/device-ok.jsp";
    }

    protected String getFailPage() {
        return "/device-fail.jsp";
    }

    @Override
    public void storeUpdates() throws IOException, SQLException {
        // no op.
    }

    protected OA2SE getServiceEnvironment() {
        return (OA2SE) MyProxyDelegationServlet.getServiceEnvironment();
    }

    public void prepare(PresentableState state) throws Throwable {
        PendingState pendingState = (PendingState) state;
        switch (pendingState.getState()) {
            case AUTHORIZATION_ACTION_OK:
                // nothing to do, really
                return;
            case AUTHORIZATION_ACTION_START:
                info("3.a. Starting authorization device");
                //Mess of information for the form
                setClientRequestAttributes(pendingState);
                return;
        }
    }

    /**
     * A class that is used by the authorization server to track user retries.
     * These only exist here and are only managed here.
     */
    public static class PendingState extends PresentationState {
        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        String username;
        String id;
        int count = 0;
        long expiresAt = 0L;

        public boolean isExpired() {
            return expiresAt < System.currentTimeMillis();
        }

        public PendingState(int state,
                            HttpServletRequest httpServletRequest,
                            HttpServletResponse httpServletResponse,
                            String id) {
            super(state, httpServletRequest, httpServletResponse);
            this.id = id;
        }
    }

    protected void setClientRequestAttributes(PendingState pendingState) {
        HttpServletRequest request = pendingState.getRequest();
        request.setAttribute(AUTHORIZATION_USER_NAME_KEY, AUTHORIZATION_USER_NAME_KEY);
        request.setAttribute(AUTHORIZATION_PASSWORD_KEY, AUTHORIZATION_PASSWORD_KEY);
        request.setAttribute(AUTHORIZATION_ACTION_KEY, AUTHORIZATION_ACTION_KEY);
        request.setAttribute(USER_CODE_KEY, USER_CODE_KEY);
        request.setAttribute("actionOk", AUTHORIZATION_ACTION_OK_VALUE);
        request.setAttribute("identifier", pendingState.id);
        request.setAttribute("count", Integer.toString(pendingState.count));
    }

    public void postprocess(PendingState pendingState) throws Throwable {
        pendingState.getResponse().setHeader("X-Frame-Options", "DENY");
    }

    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        DebugUtil.trace(this, "in RFC 8628 Authz server");
        DebugUtil.trace(this, " starting with response committed #1?" + response.isCommitted());
        PendingState pendingState = null;

        switch (getState(request)) {
            case AUTHORIZATION_ACTION_OK:
                String pageType = request.getParameter("page_type"); // since we may either have an authz page or just the consent page
                if(!StringUtils.isTrivial(pageType)){
                    if(pageType.equals("consent")){
                        // Fixes https://github.com/ncsa/oa4mp/issues/187
                        String ag = request.getParameter("code");
                        if(StringUtils.isTrivial(ag)){
                            throw new IllegalStateException("the token for the device consent page is missing");
                        }
                        AuthorizationGrantImpl authorizationGrant = TokenFactory.createAG(ag);
                        OA2SE oa2SE = (OA2SE) MyProxyDelegationServlet.getServiceEnvironment();

                        OA2ServiceTransaction trans = (OA2ServiceTransaction) oa2SE.getTransactionStore().get(authorizationGrant);
                        OA2Client resolvedClient = (OA2Client) trans.getClient(); // no ersatz possible at this point.
                        JWTRunner jwtRunner = new JWTRunner(trans, ScriptRuntimeEngineFactory.createRTE(getServiceEnvironment(), trans, resolvedClient.getConfig()));
                        OA2ClientUtils.setupHandlers(jwtRunner, getServiceEnvironment(), trans, resolvedClient, request);
                        jwtRunner.doAuthClaims();
                        oa2SE.getTransactionStore().save(trans);
                        logOK(request); //CIL-1722
                        JSPUtil.fwd(request, response, getOkPage());

                        return;
                    }
                }
                DebugUtil.trace(this, "in RFC 8628 Authz server: auth ok");
                cleanupPending(); // get rid of any old ones before looking.
                try {
                    String id = request.getParameter("identifier");
                    DebugUtil.trace(this, " starting with response committed #2?" + response.isCommitted());
                    if (StringUtils.isTrivial(id)) {
                        throw new OA2ATException(OA2Errors.INVALID_REQUEST, "no pending flow found", HttpStatus.SC_BAD_REQUEST, null);
                    }
                    DebugUtil.trace(this, " starting with response committed #3?" + response.isCommitted());
                    pendingState = pending.get(id);
                    DebugUtil.trace(this, " starting with PS response committed #3a?" + pendingState.getResponse().isCommitted());
                    if (pendingState == null) {
                        throw new OA2ATException(OA2Errors.INVALID_REQUEST, "no pending flow found", HttpStatus.SC_BAD_REQUEST, null);
                    }
                    DebugUtil.trace(this, " starting with PS response committed #4?" + pendingState.getResponse().isCommitted());
                    prepare(pendingState);
                    DebugUtil.trace(this, " starting with PS response committed #5?" + pendingState.getResponse().isCommitted());

                    pendingState.setResponse(response);
                    DebugUtil.trace(this, " starting with PS response committed #6?" + pendingState.getResponse().isCommitted());
                    processRequest(request, pendingState, true);
                    //   JSPUtil.fwd(request, response, getOkPage());
                    logOK(request); // CIL-1722

                    return;

                } catch (GeneralSecurityException t) {
                    // Generic failure
                    info("Prompting user to retry login");
                    request.setAttribute(RETRY_MESSAGE, getServiceEnvironment().getMessages().get(RETRY_MESSAGE));
                    pendingState.setState(AUTHORIZATION_ACTION_START);
                    prepare(pendingState);
                } catch (TooManyRetriesException userErrorCodeException) {
                    info("Too many retries for user code, aborting.");
                    JSPUtil.fwd(request, response, getFailPage());
                    return;
                } catch (UserLoginException | UnknownUserCodeException userLoginException) {
                    info("Prompting user to retry login");
                    if (DebugUtil.isEnabled()) {
                        userLoginException.printStackTrace();
                    }
                    request.setAttribute(RETRY_MESSAGE, userLoginException.getMessage());
                    pendingState.setState(AUTHORIZATION_ACTION_START);
                    prepare(pendingState);
                }
                break;
            case AUTHORIZATION_ACTION_START:
                DebugUtil.trace(this, "Authz action start");
                String id = BasicIdentifier.randomID().toString();
                pendingState = new PendingState(getState(request),
                        request,
                        response,
                        id);
                pendingState.count = DEFAULT_RETRY_COUNT;
                pendingState.expiresAt = System.currentTimeMillis() + getServiceEnvironment().getAuthorizationGrantLifetime();
                pending.put(id, pendingState);
                prepare(pendingState);
                // If they sent the user code with the request, do it here.
                //  printAllParameters(request);
                if (getServiceEnvironment().getAuthorizationServletConfig().isUseProxy()) {
                    DebugUtil.trace(this, "use proxy");
                    String userCode = request.getParameter(RFC8628Constants2.USER_CODE);
                    DebugUtil.trace(this, "user code = " + userCode);
                    if (StringUtils.isTrivial(userCode)) {
                        // Have to forward to a page to get it
                        // Set some attributes like the id
                        // request.setAttribute(AUTHORIZATION_USER_NAME_VALUE, escapeHtml(x));

                        JSPUtil.fwd(request, response, getRemoteUserInitialPage());
                        return;
                    } else {
                        // Have everything we need to forward to the proxy
                        userCode = userCode.toUpperCase();
                        userCode = RFC8628Servlet.convertToCanonicalForm(userCode, getServiceEnvironment().getRfc8628ServletConfig());
                        RFC8628Store<? extends OA2ServiceTransaction> rfc8628Store = (RFC8628Store) getServiceEnvironment().getTransactionStore();
                        OA2ServiceTransaction trans = rfc8628Store.getByUserCode(userCode);
                        // https://github.com/ncsa/oa4mp/issues/141
                        if (trans == null) {
                            throw new OA2ATException("access_denied", "unknown user code \"" + userCode + "\"",
                                    HttpStatus.SC_BAD_REQUEST, null);
                        }
                        MetaDebugUtil debugger = MyProxyDelegationServlet.createDebugger(trans.getOA2Client());
                        debugger.trace(this, "got transaction = " + trans);
                        printAllParameters(request, debugger);
                        // RFC 7636 support for device flow

                        try {
                            ProxyUtils.userCodeToProxyRedirect(getServiceEnvironment(), trans, pendingState);
                        } catch (Throwable t) {
                            if (t instanceof OA2GeneralError) {
                                throw t;
                            }
                            throw new OA2ATException("internal_error", t.getMessage(),
                                    HttpStatus.SC_BAD_REQUEST, trans.getRequestState(), trans.getClient());

                        }
                        return;
                    }
                }
                if (getServiceEnvironment().isDemoModeEnabled()) {
                } else {
                    if (!StringUtils.isTrivial(request.getParameter(RFC8628Constants2.USER_CODE))) {
                        processRequest(request, pendingState, false);
                        JSPUtil.fwd(request, response, getOkPage());
                        return;
                    }
                }

                break;
            default:
                // nothing to do here either.
        }
        present(pendingState);
    }

    /**
     * This is where the user's log in is actually processed and the values they sent are checked.
     *
     * @param request
     * @param pendingState
     * @param checkCount
     * @throws Throwable
     */
    protected void processRequest(HttpServletRequest request,
                                  PendingState pendingState,
                                  boolean checkCount) throws Throwable {
        ServletDebugUtil.trace(this, "starting servlet");
        ServletDebugUtil.trace(this, " starting, pending state response committed?" + pendingState.getResponse().isCommitted());
        Map<String, String> map = getFirstParameters(request);
/*        if (map.containsKey("action") && map.get("action").equals("ok")) {
            String ag = request.getParameter("authorizationGrant");
            AuthorizationGrantImpl authorizationGrant = TokenFactory.createAG(ag);
            OA2SE oa2SE = (OA2SE) MyProxyDelegationServlet.getServiceEnvironment();

            OA2ServiceTransaction trans = (OA2ServiceTransaction) oa2SE.getTransactionStore().get(authorizationGrant);
            OA2Client resolvedClient = (OA2Client) trans.getClient(); // no ersatz possible at this point.
            JWTRunner jwtRunner = new JWTRunner(trans, ScriptRuntimeEngineFactory.createRTE(getServiceEnvironment(), trans, resolvedClient.getConfig()));
            OA2ClientUtils.setupHandlers(jwtRunner, getServiceEnvironment(), trans, resolvedClient, request);
            jwtRunner.doAuthClaims();
            logOK(request); //CIL-1722
            return;
        }*/


        String userName = null;
        String password = null;
        String userCode = null;
        // Check that they have not exceeded their retry count:
        if (checkCount) {
            String counter = request.getParameter("counter");

            if (StringUtils.isTrivial(counter)) {
                throw new TooManyRetriesException("Retry attempts exceeded", "");
            }
            int count = 0;
            try {
                count = Integer.parseInt(counter);

            } catch (Throwable t) {
                throw new OA2ATException(OA2Errors.SERVER_ERROR, "counter not a number", HttpStatus.SC_INTERNAL_SERVER_ERROR, null);
            }
            if (count < 1) {
                pending.remove(pendingState.id); // remove state, so they can't retry this somehow
                ServletDebugUtil.trace(this, "user \"" + pendingState.getUsername() + "\" exceeded retry count.");
                throw new TooManyRetriesException("retry attempts exceeded", "");
            }
            pendingState.count--;

            userCode = request.getParameter(USER_CODE_KEY);             // we sent it
        } else {
            userCode = request.getParameter(RFC8628Constants2.USER_CODE);// they sent it
        }
        userCode = RFC8628Servlet.convertToCanonicalForm(userCode, getServiceEnvironment().getRfc8628ServletConfig());


        // Fixes OAUTH-192.
        if (getServiceEnvironment().getAuthorizationServletConfig().isUseHeader()) {
            String headerName = getServiceEnvironment().getAuthorizationServletConfig().getHeaderFieldName();
            if (StringUtils.isTrivial(headerName) || headerName.toLowerCase().equals("remote_user")) {
                userName = request.getRemoteUser();
            } else {
                Enumeration enumeration = request.getHeaders(headerName);
                if (!enumeration.hasMoreElements()) {
                    throw new OA2ATException(OA2Errors.ACCESS_DENIED,
                            "A custom header of \"" + headerName + "\" was specified for authorization, but no value was found.",
                            HttpStatus.SC_UNAUTHORIZED, null);
                }
                userName = enumeration.nextElement().toString();
                if (enumeration.hasMoreElements()) {
                    throw new OA2ATException(OA2Errors.ACCESS_DENIED,
                            "A custom header of \"" + headerName + "\" was specified for authorization, but multiple values were found.",
                            HttpStatus.SC_UNAUTHORIZED, null);
                }
            }
            if (getServiceEnvironment().getAuthorizationServletConfig().isRequireHeader()) {
                if (StringUtils.isTrivial(userName)) {
                    warn("Headers required, but none found.");
                    throw new OA2ATException(OA2Errors.ACCESS_DENIED,
                            "Headers required, but none found.",
                            HttpStatus.SC_UNAUTHORIZED, null);
                }
            } else {
                // So the score card is that the header is not required though use it if there for the username
                if (StringUtils.isTrivial(userName)) {
                    userName = request.getParameter(AUTHORIZATION_USER_NAME_KEY);
                }
            }
        } else {
            if (!getServiceEnvironment().getAuthorizationServletConfig().isUseProxy()) {
                // Headers, proxy not used, just pull it off the form the user POSTs.
                userName = request.getParameter(AUTHORIZATION_USER_NAME_KEY);
                password = request.getParameter(AUTHORIZATION_PASSWORD_KEY);
                if (DEBUG_LOGIN) {
                    debugCheckUser(userName, password);
                } else {
                    checkUser(userName, password);
                }
                pendingState.setUsername(userName);
            }
        }

        if (!StringUtils.isTrivial(userCode)) {
            userCode = userCode.toUpperCase();
        }
        DebugUtil.trace(this, " getting transaction, pending state response committed?" + pendingState.getResponse().isCommitted());

        RFC8628Store<? extends OA2ServiceTransaction> rfc8628Store = (RFC8628Store) getServiceEnvironment().getTransactionStore();
        OA2ServiceTransaction trans = rfc8628Store.getByUserCode(userCode);
        if (checkCount && trans == null) {
            if (pendingState.count == 0) {
                throw new TooManyRetriesException("number of retries has been been reached,", userCode);
            }
            throw new UnknownUserCodeException("unknown user code", userCode);
        }
        if (trans.getAuthorizationGrant().isExpired()) {
            throw new OA2ATException(OA2Errors.INVALID_GRANT, "expired grant", HttpStatus.SC_BAD_REQUEST, null,
                    trans.getClient());
        }
        if (!trans.isAuthGrantValid()) {
            throw new OA2ATException(OA2Errors.INVALID_GRANT, "grant is invalid", HttpStatus.SC_BAD_REQUEST, null,
                    trans.getClient());
        }
        MetaDebugUtil debugger = MyProxyDelegationServlet.createDebugger(trans.getOA2Client());
        if (debugger instanceof ClientDebugUtil) {
            ((ClientDebugUtil) debugger).setTransaction(trans);
        }
        debugger.trace(this, "processRequest committed?" + pendingState.getResponse().isCommitted());
        if (!trans.isRFC8628Request()) {
            //So there is such a grant but somehow this is not a valid rfc 8628 request. Should not happen, but if someone edited
            // the transaction itself and made a mistake, it could, in which case the state of the request itself is questionable.
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "invalid request", HttpStatus.SC_BAD_REQUEST, null,
                    trans.getClient());
        }
        if (getServiceEnvironment().getAuthorizationServletConfig().isUseProxy()) {
            // If this is a proxy, forward the user to do the login. we have to have gotten the transaction
            // to do this.
            try {
                debugger.trace(this, "processRequest calling userCodeToProxy");
                ProxyUtils.userCodeToProxyRedirect(getServiceEnvironment(), trans, pendingState);
                return;
            } catch (Throwable t) {
                if (t instanceof OA2GeneralError) {
                    throw t;
                }
                throw new OA2ATException("internal_error", t.getMessage(),
                        HttpStatus.SC_BAD_REQUEST, null, trans.getClient());

            }
        }
        trans.setUsername(userName);
        RFC8628State rfc8628State = trans.getRFC8628State();
        rfc8628State.valid = true; // means they actually logged in
        // The JSON library copies everything no matter what, so no guarantee what's in the transaction is the same object.
        // Just replace it with the good copy.
        trans.setRFC8628Request(false); // or it gets picked up when rebuilding the cache as outstanding.
        trans.setRFC8628State(rfc8628State);
        pending.remove(pendingState.id); // clean that out
        trans.setValidatedScopes(trans.getScopes()); // At this point they accepted the scopes on the consent page, so stash them.
/*        OA2Client resolvedClient = (OA2Client)trans.getClient(); // no ersatz possible at this point.
        JWTRunner jwtRunner = new JWTRunner(trans, ScriptRuntimeEngineFactory.createRTE(getServiceEnvironment(), trans, resolvedClient.getConfig()));
        OA2ClientUtils.setupHandlers(jwtRunner, getServiceEnvironment(), trans, resolvedClient, request);
        jwtRunner.doAuthClaims();*/
        getServiceEnvironment().getTransactionStore().save(trans);
        setClientConsentAttributes(request, trans);
        JSPUtil.fwd(request, pendingState.getResponse(), getConsentPage());
    }

    public static class TooManyRetriesException extends GeneralException {
        String userCode;

        public TooManyRetriesException(String message, String userCode) {
            super(message);
            this.userCode = userCode;
        }
    }

    public static class UnknownUserCodeException extends GeneralException {
        String userCode;

        public UnknownUserCodeException(String message, String userCode) {
            super(message);
            this.userCode = userCode;
        }
    }

    // Only set to true if you are debugging the login machinery.
    // It then allows exactly one user -- me -- to authenticate.
    boolean DEBUG_LOGIN = false;

    public void debugCheckUser(String username, String password) throws GeneralSecurityException {
        if (username.equals("jeff") && password.equals("changeme")) {
            System.err.println(this.getClass().getSimpleName() + ": DEBUG_LOGIN FOR 'jeff' ONLY enabled");
            return;
        }
    }


    public void checkUser(String username, String password) throws GeneralSecurityException {
        // At this point in the basic servlet, there is no system for passwords.
        // This is because OA4MP has no native concept of managing users, it being
        // far outside of the OAuth spec.
        if (getServiceEnvironment().isDemoModeEnabled()) {
            // In demo mode, this will display the pages and accept the username (so the subject
            // gets set
            // but no password protection of any sort is done. Demo mode really is just intended
            // so that an admin can set up an instance of OA4MP to evaluate if it fits their needs.
            info("demo mode enabled, no authorization is being used.");
        } else {
            // If you were checking users and there  were a problem, you would do this:
            String message = "invalid login";
            throw new OA2ATException(OA2Errors.ACCESS_DENIED, message, HttpStatus.SC_UNAUTHORIZED, null);
            // which would display the message as the retry message.
        }
    }


    Map<String, PendingState> pending = new HashMap<>();

    public void present(PresentableState state) throws Throwable {
        PendingState pendingState = (PendingState) state;
        postprocess(pendingState);

        switch (pendingState.getState()) {
            case AUTHORIZATION_ACTION_START:
                String initPage = getInitialPage();
                info("*** STARTING present");
                if (getServiceEnvironment().getAuthorizationServletConfig().isUseHeader()) {
                    initPage = getRemoteUserInitialPage();

                    info("*** PRESENT: Use headers enabled.");
                    String x = null;
                    if (getServiceEnvironment().getAuthorizationServletConfig().getHeaderFieldName().equals("REMOTE_USER")) {
                        // slightly more surefire way to get this.
                        x = pendingState.getRequest().getRemoteUser();
                        info("*** got user name from request = " + x);
                    } else {
                        x = pendingState.getRequest().getHeader(getServiceEnvironment().getAuthorizationServletConfig().getHeaderFieldName());
                        info("Got username from header \"" + getServiceEnvironment().getAuthorizationServletConfig().getHeaderFieldName() + "\" + directly: " + x);
                    }

                    if (StringUtils.isTrivial(x)) {
                        if (getServiceEnvironment().getAuthorizationServletConfig().isRequireHeader()) {
                            throw new GeneralException("Error: configuration required using the header \"" +
                                    getServiceEnvironment().getAuthorizationServletConfig().getHeaderFieldName() + "\" " +
                                    "but this was not set. Cannot continue."
                            );
                        }
                        // not required, it is null

                    } else {
                        // name is set. optional or required
                        pendingState.setUsername(x);
                        info("*** storing user name = " + x);
                        //getTransactionStore().save(aState.getTransaction());

                        // make it display pretty as per usual conventions. This is never reused, however.
                        pendingState.getRequest().setAttribute(AUTHORIZATION_USER_NAME_VALUE, StringEscapeUtils.escapeHtml(x));
                    }
                } else {
                    info("*** PRESENT: Use headers DISABLED.");

                }
                JSPUtil.fwd(state.getRequest(), state.getResponse(), initPage);
                info("3.a. User information obtained for grant = " + pendingState.id);
                break;
            case AUTHORIZATION_ACTION_OK:
                JSPUtil.fwd(state.getRequest(), state.getResponse(), getOkPage());
                break;
            default:
                // fall through and do nothing
                debug("Hit default case in " + this.getClass().getSimpleName() + " servlet");
        }
    }


    protected void cleanupPending() {
        if (pending == null || pending.isEmpty()) {
            return;
        }
        // have to do it in stages or risk a concurrent modification exception.
        List<String> tempKeys = new LinkedList<>();
        for (String key : pending.keySet()) {
            if (pending.get(key).isExpired()) {
                tempKeys.add(key);
            }
        }
        for (String key : tempKeys) {
            pending.remove(key);

        }
    }

    protected void setClientConsentAttributes(HttpServletRequest request, OA2ServiceTransaction t) {
       /*request.setAttribute(AUTHORIZATION_USER_NAME_KEY, AUTHORIZATION_USER_NAME_KEY);
        request.setAttribute(AUTHORIZATION_PASSWORD_KEY, AUTHORIZATION_PASSWORD_KEY);*/
        request.setAttribute(AUTHORIZATION_ACTION_KEY, AUTHORIZATION_ACTION_KEY);
        request.setAttribute("actionOk", AUTHORIZATION_ACTION_OK_VALUE);
        request.setAttribute("authorizationGrant", t.getIdentifierString());
        request.setAttribute("tokenKey", CONST(TOKEN_KEY));
        // OAuth 2.0 specific values that must be preserved.
        request.setAttribute("stateKey", "state");
        request.setAttribute("authorizationState", t.getRequestState());

        request.setAttribute("clientHome", escapeHtml(t.getClient().getHomeUri()));
        request.setAttribute("clientName", escapeHtml(t.getClient().getName()));
        request.setAttribute("clientScopes", StringEscapeUtils.escapeHtml(scopesToString(t)));

        request.setAttribute("actionToTake", request.getContextPath() + "/device");
    }

    public static String CONSENT_PAGE = "/device-consent.jsp";

    protected String getConsentPage() {
        return CONSENT_PAGE;
    }

}
