package edu.uiuc.ncsa.myproxy.oa4mp.server.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.server.util.NewClientEvent;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.NewClientListener;
import edu.uiuc.ncsa.security.core.exceptions.RetryException;
import edu.uiuc.ncsa.oa4mp.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.oa4mp.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.oa4mp.delegation.common.servlet.TransactionState;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.BaseClient;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.Client;
import edu.uiuc.ncsa.security.servlet.*;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/3/14 at  10:46 AM
 */
public abstract class AbstractRegistrationServlet extends MyProxyDelegationServlet implements Presentable {

    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
        return null;
    }

    public static final String CLIENT_NAME = "clientName";
    public static final String CLIENT_PUBLIC_KEY = "clientPublicKey";
    public static final String CLIENT_HOME_URL = "clientHomeUrl";
    public static final String CLIENT_ERROR_URL = "clientErrorUrl";
    public static final String CLIENT_EMAIL = "clientEmail";
    public static final String CLIENT_PROXY_LIMITED = "clientProxyLimited";
    // https://github.com/rcauth-eu/OA4MP/commit/9d6c3afa87adadb48c9c7df2d078f3890b8ae9b0 -- removed unused constant
    public static final String CLIENT_IS_PUBLIC = "clientIsPublic";
    public static final String CLIENT_ACTION_KEY = "action";
    public static final String CLIENT_ACTION_REQUEST_VALUE = "request";

    protected static final int INITIAL_STATE = 0;
    protected static final int ERROR_STATE = -1;
    protected static final int REQUEST_STATE = 100;

    public int getState(HttpServletRequest request) {
        String action = request.getParameter(CLIENT_ACTION_KEY);
        if (action == null || action.length() == 0) return INITIAL_STATE;
        if (action.equals(CLIENT_ACTION_REQUEST_VALUE)) return REQUEST_STATE;
        return ERROR_STATE; // something is wrong with the request or state,
    }

    protected void fireNewClientEvent(NewClientEvent newClientEvent) {
        for (NotificationListener notificationListener : notificationListeners) {
            if (notificationListener instanceof NewClientListener) {
                ((NewClientListener) notificationListener).fireNewClientEvent(newClientEvent);
            }
        }
    }

    public void prepare(PresentableState state) throws Throwable {
        preprocess(new TransactionState(state.getRequest(), state.getResponse(), null, null, null));
        switch (state.getState()) {
            case INITIAL_STATE:
                HttpServletRequest request = state.getRequest();
                info("Processing new client registration request.");
                request.setAttribute(CLIENT_NAME, CLIENT_NAME);
                request.setAttribute(CLIENT_PUBLIC_KEY, CLIENT_PUBLIC_KEY);
                request.setAttribute(CLIENT_HOME_URL, CLIENT_HOME_URL);
                request.setAttribute(CLIENT_ERROR_URL, CLIENT_ERROR_URL);
                request.setAttribute(CLIENT_EMAIL, CLIENT_EMAIL);
                request.setAttribute(CLIENT_PROXY_LIMITED, CLIENT_PROXY_LIMITED);
                request.setAttribute(CLIENT_IS_PUBLIC, CLIENT_IS_PUBLIC);


                request.setAttribute(CLIENT_ACTION_KEY, CLIENT_ACTION_KEY);
                request.setAttribute(CLIENT_ACTION_REQUEST_VALUE, CLIENT_ACTION_REQUEST_VALUE);
                System.out.println("context path = " + request.getContextPath() + ", servlet path =" + request.getServletPath() + ", request utl = " + request.getRequestURL()); 
                request.setAttribute("actionToTake", request.getContextPath() + request.getServletPath());
                break;
            case REQUEST_STATE:
                // nothing to do.
                return;
            case ERROR_STATE:
            default:
                warn("Error: unknown action request.");
        }
    }

    /**
     * The page to display to the client for the initial request.
     */
    public static String INIT_PAGE = "/registration-init.jsp";
    protected String getInitPage(){
        return INIT_PAGE;
    }

    /**
     * The name of a JSP page to display in  case of errors. The default is "registration-error.jsp".
     */
    public static String ERROR_PAGE = "/registration-error.jsp";
    protected String getErrorPage(){
        return ERROR_PAGE;
    }

    /**
     * If the registration works, this is the page to display to the user afterwards.
     */

    public static String OK_PAGE = "/registration-ok.jsp";
    protected String getOKPage(){
        return OK_PAGE;
    }


    public void present(PresentableState state) throws Throwable {
        postprocess(new TransactionState(state.getRequest(), state.getResponse(), null, null, null));

        switch (state.getState()) {
            case INITIAL_STATE:
                JSPUtil.fwd(state.getRequest(), state.getResponse(), getInitPage());
                break;
            case REQUEST_STATE:
                if (state instanceof ClientState) {
                    ClientState cState = (ClientState) state;
                    state.getRequest().setAttribute("client", cState.getClient());
                    JSPUtil.fwd(state.getRequest(), state.getResponse(), getOKPage());
                } else {
                    throw new IllegalStateException("Error: An instance of ClientState was expected, but got an instance of \"" + state.getClass().getName() + "\"");
                }
                break;
            case ERROR_STATE:
            default:
        }
    }

    public void handleError(PresentableState state, Throwable t) throws IOException, ServletException {
        state.getResponse().setHeader("X-Frame-Options", "DENY");
        JSPUtil.handleException(t, state.getRequest(), state.getResponse(), getErrorPage());
    }

    protected static class ClientState extends PresentationState {
        ClientState(int state,
                    HttpServletRequest request,
                    HttpServletResponse response,
                    BaseClient client) {
            super(state, request, response);
            this.client = client;
        }

        public BaseClient getClient() {
            return client;
        }

        BaseClient client;
    }

    /**
     * For a key (e.g. clientName) the associated form value is usually name+"Value" (e.g. clientNameValue).
     * This method creates these value tags.
     *
     * @param key
     * @return
     */
    protected String getValueTag(String key) {
        return key + "Value";
    }

    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        if (!request.isSecure()) {
            // Tomcat docs say to explicitly check here for the right protocol if it is truly required.
            throw new ServletException("Unsupported protocol");
        }
        int state = getState(request);
        // Addresses
        if (state == INITIAL_STATE) {
            if (getServiceEnvironment().getMaxAllowedNewClientRequests() <= getServiceEnvironment().getClientApprovalStore().getPendingCount()) {
                // https://github.com/rcauth-eu/OA4MP/commit/153177ccd0a2f5d0aa558cca4d4b7c4dc442065a change to send to the log.
                error("Too many client approvals pending. Max allowed unapproved count is " + getServiceEnvironment().getMaxAllowedNewClientRequests());
                // Fixes CIL-414, CIL-426 (send email notification), CIL-427

                getServiceEnvironment().getMailUtil().sendMessage("Too many pending approvals",
                        request.getServerName() + " has too many pending client approval requests outstanding. " +
                                "The server is configured for a limit of " + getServiceEnvironment().getMaxAllowedNewClientRequests() + " and"
                                + " there are " + getServiceEnvironment().getClientApprovalStore().getPendingCount() + " pending approvals in the store.", null);
                JSPUtil.fwd(request, response, "/tooManyClientRequests.jsp");
                // Fixes OAUTH-90 bug.
                return;
            }
        }

        PresentationState pState = new PresentationState(state, request, response);
        try {
            prepare(pState);
            if (state == REQUEST_STATE) {
                BaseClient client = addNewClient(request, response);
                // Fix for OAUTH-157 bug. Always save any updates to the client
                save(client);
                pState = new ClientState(state, request, response, client);
            }
            present(pState);
        } catch (ClientRegistrationRetryException r) {
            getServiceEnvironment().getClientStore().remove(r.getClient().getIdentifier());
            setRetryParameters(request, r);
            if ((request.getAttribute(getValueTag(CLIENT_PROXY_LIMITED)) != null) && request.getAttribute(getValueTag(CLIENT_PROXY_LIMITED)).equals("on")) {
                request.setAttribute(getValueTag(CLIENT_PROXY_LIMITED), "checked"); // so this is checked
            } else {
                request.removeAttribute(getValueTag(CLIENT_PROXY_LIMITED)); // so this is unchecked

            }
            request.setAttribute(CLIENT_NAME, CLIENT_NAME);
            // Next commands reset the state on the form so the contents are processed.
            request.setAttribute(CLIENT_ACTION_KEY, CLIENT_ACTION_KEY);
            request.setAttribute(CLIENT_ACTION_REQUEST_VALUE, CLIENT_ACTION_REQUEST_VALUE);
            //request.setAttribute("actionToTake", request.getContextPath() + "/register");
            // Don't hard-code /register in case they deploy it elsewhere.
            request.setAttribute("actionToTake", request.getContextPath() + request.getServletPath());


            request.setAttribute("retryMessage", r.getMessage());

            JSPUtil.fwd(request, response, getInitPage());
        } catch (Throwable t) {
            if (ServletDebugUtil.isEnabled()) {
                t.printStackTrace();
            }
            warn("Error registering a new client:" + t.getMessage());
            handleError(pState, t);
        }
    }

    protected void save(BaseClient client){
        getServiceEnvironment().getClientStore().save((Client)client);
    }
    /**
     * Sets the parameters from the request so they can be passed back.
     *
     * @param request
     * @param r
     */
    protected void setRetryParameters(HttpServletRequest request, RetryException r) {
        for (Object p : request.getParameterMap().keySet()) {
            if (p != null) {
                String key = p.toString();
                request.setAttribute(key, key);
                request.setAttribute(getValueTag(key), request.getParameter(key));
            }
        }
    }

    protected String getParameter(HttpServletRequest req, String key) {
        return req.getParameter(key);
    }

    protected String getRequiredParam(HttpServletRequest req, String key, BaseClient client) {
        String x = getParameter(req, key);
        if (x == null || x.length() == 0) {
            throw new ClientRegistrationRetryException("Error: missing value for " + key, null, client);
        }
        return x;
    }

    boolean getBooleanParam(HttpServletRequest req, String key) {
        String x = req.getParameter(key);
        if (x == null || x.length() == 0) {
            return false;
        }
        return Boolean.parseBoolean(x);

    }

    protected String emailPattern = "^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@((\\[[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\])|(([a-zA-Z\\-0-9]+\\.)+[a-zA-Z]{2,}))$";



    protected BaseClient setupNewClient(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        // Assumption is that the request is in good order and we just have to pull stuff off it.
        Client client = getServiceEnvironment().getClientStore().create();
        info("creating entry for client=" + client.getIdentifierString());
        // Fill in as much info as we can before parsing public key.
        // We always store exactly what was given to us, though later we html escape it to
        // prevent against HTML injection attacks (fixes bug OAUTH-87).
        client.setName(getRequiredParam(request, CLIENT_NAME, client));
        client.setHomeUri(getRequiredParam(request, CLIENT_HOME_URL, client));
        String x = getRequiredParam(request, CLIENT_EMAIL, client);
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(emailPattern);
        java.util.regex.Matcher m = p.matcher(x);
        if (!m.matches()) {
            throw new ClientRegistrationRetryException("The email address \"" + x + "\" is not valid.", null, client);
        }
        client.setEmail(x);

        //client.setProxyLimited(getBooleanParam(request, CLIENT_PROXY_LIMITED));
        //https://github.com/rcauth-eu/OA4MP/commit/4d80fe4969d487719a35cda1faa8d603340b19b3
        String limitedChecked=getParameter(request, CLIENT_PROXY_LIMITED);
         client.setProxyLimited(limitedChecked != null && limitedChecked.equals("on"));

        getServiceEnvironment().getClientStore().save(client);
        info("Adding approval record for client=" + client.getIdentifierString());
        ClientApproval clientApproval = new ClientApproval(client.getIdentifier());
        clientApproval.setApproved(false);

        info("done with client registration, client=" + client.getIdentifierString());
        return client;
    }

    protected BaseClient addNewClient(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        // Fix for CIL-169: the last thing that should be done after this is over-ridden is to fire a new client event:
        //            fireNewClientEvent(client);
        // Failure to do so will turn off the ability to email new client registrations!
        // So invoke setupNewClient to create one, have your call over-ride this and fire the event,

        return setupNewClient(request, response);

    }


    // Fixes CIL-286: Send along the client in the exception so it can be removed immediately rather
    // than garbage collected later.

    public static class ClientRegistrationRetryException extends RetryException {
        public BaseClient getClient() {
            return client;
        }

        BaseClient client;

        public ClientRegistrationRetryException(String message, Throwable cause, BaseClient client) {
            super(message, cause);
            this.client = client;
        }
    }
}
