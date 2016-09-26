package edu.uiuc.ncsa.myproxy.oa4mp.server.servlet;

import edu.uiuc.ncsa.myproxy.NoUsableMyProxyServerFoundException;
import edu.uiuc.ncsa.security.core.exceptions.ConnectionException;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.DateUtils;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.delegation.servlet.TransactionState;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.servlet.JSPUtil;
import edu.uiuc.ncsa.security.servlet.Presentable;
import edu.uiuc.ncsa.security.servlet.PresentableState;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Map;

import static edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceConstantKeys.TOKEN_KEY;
import static org.apache.commons.lang.StringEscapeUtils.escapeHtml;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/14/14 at  11:50 AM
 */
public abstract class AbstractAuthroizationServlet extends CRServlet implements Presentable {
    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
        return null;
    }

    /**
     * This will take whatever the passed in callback from the client is and append any parameters needed.
     * Generally these parameters are protocol specific.
     *
     * @param transaction
     * @return
     */
    public abstract String createCallback(ServiceTransaction transaction, Map<String, String> params);

    public static final String AUTHORIZATION_ACTION_KEY = "action";
    public static final String AUTHORIZATION_USER_NAME_KEY = "AuthUserName";
    public static final String AUTHORIZATION_USER_NAME_VALUE = "userName"; // only used for setting the username, if it comes in a header.
    public static final String AUTHORIZATION_PASSWORD_KEY = "AuthPassword";
    public static final String AUTHORIZATION_ACTION_OK_VALUE = "ok";
    public static final int AUTHORIZATION_ACTION_OK = 1;
    public static final int AUTHORIZATION_ACTION_START = 0;
    public static final String RETRY_MESSAGE = "retryMessage";

    /**
     * State object after authorization has worked.
     */
    protected class AuthorizedState extends PresentationState {
        public AuthorizedState(int state, HttpServletRequest request, HttpServletResponse response, ServiceTransaction transaction) {
            super(state, request, response);
            this.transaction = transaction;
        }


        public ServiceTransaction getTransaction() {
            return transaction;
        }

        ServiceTransaction transaction;
    }

    public void prepare(PresentableState state) throws Throwable {
        AuthorizedState aState = (AuthorizedState) state;
        switch (aState.getState()) {
            case AUTHORIZATION_ACTION_OK:
                // nothing to do, really
                return;
            case AUTHORIZATION_ACTION_START:
                info("3.a. Starting authorization for grant =" + aState.getTransaction().getIdentifierString());
                //Mess of information for the form
                HttpServletRequest request = state.getRequest();

                request.setAttribute(AUTHORIZATION_USER_NAME_KEY, AUTHORIZATION_USER_NAME_KEY);
                request.setAttribute(AUTHORIZATION_PASSWORD_KEY, AUTHORIZATION_PASSWORD_KEY);
                request.setAttribute(AUTHORIZATION_ACTION_KEY, AUTHORIZATION_ACTION_KEY);
                request.setAttribute("actionOk", AUTHORIZATION_ACTION_OK_VALUE);
                request.setAttribute("authorizationGrant", aState.getTransaction().getIdentifierString());
                request.setAttribute("tokenKey", CONST(TOKEN_KEY));
                // OAuth 2.0 specific values that must be preserved.
                request.setAttribute("stateKey", "state");
                request.setAttribute("authorizationState", getParam(aState.getRequest(), "state"));
                // HTML escape it to guard against HTML injection attacks. Addresses issue OAUTH-87.
                // If you aren't sure whether a form is secure against HTML injection attacks, paste the following into it:
                // ><script>alert('CSS Vulnerable')</script><b a=a     a></a><script>alert('CSS Vulnerable')</script>     \'><script>alert%28\'CSS Vulnerable\'%29</script><
                // and get the form to re-display. If it is vulnerable, a popup saying so will appear.

                request.setAttribute("clientHome", escapeHtml(aState.getTransaction().getClient().getHomeUri()));
                request.setAttribute("clientName", escapeHtml(aState.getTransaction().getClient().getName()));
                request.setAttribute("actionToTake", request.getContextPath() + "/authorize");
                return;
        }
    }

    public static String INITIAL_PAGE = "/authorize-init.jsp";
    public static String OK_PAGE = "/authorize-ok.jsp";
    public static String ERROR_PAGE = "/authorize-error.jsp";

    public void present(PresentableState state) throws Throwable {
        AuthorizedState aState = (AuthorizedState) state;
        postprocess(new TransactionState(state.getRequest(), aState.getResponse(), null, aState.getTransaction()));

        switch (aState.getState()) {
            case AUTHORIZATION_ACTION_START:
                String initPage = INITIAL_PAGE;
                info("*** STARTING present");
                if (getServiceEnvironment().getAuthorizationServletConfig().isUseHeader()) {
                    info("*** PRESENT: Use headers enabled.");
                    String x = null;
                    if (getServiceEnvironment().getAuthorizationServletConfig().getHeaderFieldName().equals("REMOTE_USER")) {
                        // slightly more surefire way to get this.
                        x = aState.getRequest().getRemoteUser();
                        info("*** got user name from request = " + x);
                    } else {
                        x = aState.getRequest().getHeader(getServiceEnvironment().getAuthorizationServletConfig().getHeaderFieldName());
                        info("Got username from header \"" + getServiceEnvironment().getAuthorizationServletConfig().getHeaderFieldName() + "\" + directly: " + x);
                    }

                    if (isEmpty(x)) {
                        if (getServiceEnvironment().getAuthorizationServletConfig().isRequireHeader()) {
                            throw new GeneralException("Error: configuration required using the header \"" +
                                    getServiceEnvironment().getAuthorizationServletConfig().getHeaderFieldName() + "\" " +
                                    "but this was not set. Cannot continue."
                            );
                        }
                        // not required, it is null

                    } else {
                        // name is set. optional or required
                        aState.getTransaction().setUsername(x);
                        info("*** storing user name = " + x);
                        getTransactionStore().save(aState.getTransaction());

                        // make it display pretty as per usual conventions. This is never reused, however.
                        aState.getRequest().setAttribute(AUTHORIZATION_USER_NAME_VALUE, escapeHtml(x));
                    }
                } else {
                    info("*** PRESENT: Use headers DISABLED.");

                }
                JSPUtil.fwd(state.getRequest(), state.getResponse(), initPage);
                info("3.a. User information obtained for grant = " + aState.getTransaction().getAuthorizationGrant());
                break;
            case AUTHORIZATION_ACTION_OK:
                JSPUtil.fwd(state.getRequest(), state.getResponse(), OK_PAGE);
                break;
            default:
                // fall through and do nothing
                debug("Hit default case in AbstractAuthZ servlet");
        }
    }


    public void handleError(PresentableState state, Throwable t) throws IOException, ServletException {
        AuthorizedState aState = (AuthorizedState) state;
        state.getResponse().setHeader("X-Frame-Options", "DENY");
        state.getRequest().setAttribute("client", aState.getTransaction().getClient());
        JSPUtil.handleException(t, state.getRequest(), state.getResponse(), ERROR_PAGE);
    }

    protected String getParam(HttpServletRequest request, String key) {
        String x = null;
        x = request.getParameter(key);
        if (x != null) return x;
        Object oo = request.getAttribute(key);
        if (oo != null) {
            x = oo.toString();
        }
        return x;
    }

    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        info("*** STARTING request");
        //String ag = request.getParameter(CONST(TOKEN_KEY));
        String ag = getParam(request, CONST(TOKEN_KEY));
        ServiceTransaction trans = null;

        if (ag == null) {
            throw new GeneralException("Error: Invalid request -- no token. Request rejected.");
        }
        trans = getAndCheckTransaction(ag);
        AuthorizedState pState = new AuthorizedState(getState(request), request, response, trans);
        prepare(pState);
        preprocess(new TransactionState(request, response, null, trans));

        switch (pState.getState()) {
            case AUTHORIZATION_ACTION_OK:
                trans.setAuthGrantValid(true); // As per the spec, if the code gets to here then authentication worked.
                getTransactionStore().save(trans);
                // get the cert and store it. Then forward user.
                try {
                    createRedirect(request, response, trans);
                    // There is nothing to present, since the spec requires a redirect
                    // at this point.
                    return;

                } catch (ConnectionException ce) {
                    request.setAttribute(RETRY_MESSAGE, getServiceEnvironment().getMessages().get(RETRY_MESSAGE));
                    pState.setState(AUTHORIZATION_ACTION_START);
                    prepare(pState);

                } catch (GeneralSecurityException | NoUsableMyProxyServerFoundException t) { //CIL-173 fix: process NoUsableMPSFound.
                    info("Prompting user to retry");
                    request.setAttribute(RETRY_MESSAGE, getServiceEnvironment().getMessages().get(RETRY_MESSAGE));
                    pState.setState(AUTHORIZATION_ACTION_START);
                    prepare(pState);
                }
                break;
            case AUTHORIZATION_ACTION_START:
                // no processing needed for initial request.
                break;
            default:
                // nothing to do here either.
        }
        present(pState);
    }

    public int getState(HttpServletRequest request) {
        String action = request.getParameter(AUTHORIZATION_ACTION_KEY);
        log("action = " + action);
        if (action == null || action.length() == 0) return AUTHORIZATION_ACTION_START;
        if (action.equals(AUTHORIZATION_ACTION_OK_VALUE)) return AUTHORIZATION_ACTION_OK;
        throw new GeneralException("Error: unknown authorization request action = \"" + action + "\"");
    }

    /*
         Get the transaction associated with the authorization grant token and check that it passes sanity
         checks. If so, return it, If not, throw the appropriate exception.
     */
    protected ServiceTransaction getAndCheckTransaction(String token) throws IOException {
        DateUtils.checkTimestamp(token);
        AuthorizationGrant grant = MyProxyDelegationServlet.getServiceEnvironment().getTokenForge().getAuthorizationGrant(token);
        ServiceTransaction trans = MyProxyDelegationServlet.getServiceEnvironment().getTransactionStore().get(grant);
        if (trans == null) {
            warn("Error: no delegation request found for " + token);
            throw new GeneralException("Error: no delegation request found.");
        }
        checkClient(trans.getClient());
        return trans;
    }


    protected void createRedirect(HttpServletRequest request, HttpServletResponse response, ServiceTransaction trans) throws Throwable {
        String userName = request.getParameter(AUTHORIZATION_USER_NAME_KEY);
        trans.setUsername(userName);

        String password = request.getParameter(AUTHORIZATION_PASSWORD_KEY);
        info("3.b. transaction has user name = " + userName);
        // The right place to invoke the pre-processor.
        preprocess(new TransactionState(request, response, null, trans));
        String statusString = " transaction =" + trans.getIdentifierString() + " and client=" + trans.getClient().getIdentifierString();
        trans.setVerifier(MyProxyDelegationServlet.getServiceEnvironment().getTokenForge().getVerifier());
        MyProxyDelegationServlet.getServiceEnvironment().getTransactionStore().save(trans);

        createMPConnection(trans.getIdentifier(), userName, password, trans.getLifetime(), statusString);
        doRealCertRequest(trans, statusString);
        debug("4.a. verifier = " + trans.getVerifier() + ", " + statusString);
        String cb = createCallback(trans, getFirstParameters(request));
        info("4.a. starting redirect to " + cb + ", " + statusString);
        response.sendRedirect(cb);
        info("4.b. Redirect to callback " + cb + " ok, " + statusString);
    }

}
