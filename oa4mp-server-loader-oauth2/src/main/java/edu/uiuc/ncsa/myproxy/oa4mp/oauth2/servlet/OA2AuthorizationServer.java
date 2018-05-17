package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;


import edu.uiuc.ncsa.myproxy.MPSingleConnectionProvider;
import edu.uiuc.ncsa.myproxy.MyProxyConnectable;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.OA2ClaimsUtil;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.OA2FunctorFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.FlowStates;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.OA2ClientConfiguration;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.OA2ClientConfigurationFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractAuthorizationServlet;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.oauth_2_0.*;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.servlet.PresentableState;
import net.sf.json.JSONObject;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.List;
import java.util.Map;


/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/7/14 at  11:44 AM
 */
public class OA2AuthorizationServer extends AbstractAuthorizationServlet {
    @Override
    protected AccessToken getAccessToken(HttpServletRequest request) {
        throw new NotImplementedException("No access token is available");
    }

    public String AUTHORIZATION_REFRESH_TOKEN_LIFETIME_KEY = "AuthRTL";
    public String AUTHORIZED_ENDPOINT = "/authorized";
    public String AUTHORIZATION_REFRESH_TOKEN_LIFETIME_VALUE = "rtLifetime";

    /**
     * This class is needed to pass information between servlets, where one servlet
     * calls another.
     */
    static class MyHttpServletResponseWrapper
            extends HttpServletResponseWrapper {

        private StringWriter sw = new StringWriter();

        public MyHttpServletResponseWrapper(HttpServletResponse response) {
            super(response);
        }

        int internalStatus = 0;

        @Override
        public void setStatus(int sc) {
            internalStatus = sc;
            super.setStatus(sc);
            if (!(200 <= sc && sc < 300)) {
                setExceptionEncountered(true);
            }
        }

        public int getStatus() {
            return internalStatus;
        }

        public PrintWriter getWriter() throws IOException {
            return new PrintWriter(sw);
        }

        public ServletOutputStream getOutputStream() throws IOException {
            throw new UnsupportedOperationException();
        }

        public String toString() {
            return sw.toString();
        }

        /**
         * If in the course of processing an exception is encountered, set this to be true. This class
         * is made to be passed between servlets and the results harvested, but if one of the servlets encounters
         * an exception, that is handled with a redirect (in OAuth 2) so nothing ever gets propagated back up the
         * stack to show that. This should be checked to ensure that did not happen.
         *
         * @return
         */
        boolean isExceptionEncountered() {
            return exceptionEncountered;
        }

        void setExceptionEncountered(boolean exceptionEncountered) {
            this.exceptionEncountered = exceptionEncountered;
        }

        boolean exceptionEncountered = false;
    }

    protected OA2AuthorizedServletUtil getInitUtil(){
        return new OA2AuthorizedServletUtil(this);
    }

    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        Map<String, String> map = getFirstParameters(request);

        //printAllParameters(request);
        if (map.containsKey(OA2Constants.RESPONSE_TYPE)) {
            // Probably means this is an initial request. Pass it along to the init util to
            // unscramble it.
            MyHttpServletResponseWrapper wrapper = new MyHttpServletResponseWrapper(response);
            OA2AuthorizedServletUtil init = getInitUtil();
            init.doDelegation(request, wrapper);
           // JSPUtil.fwd(request, wrapper, AUTHORIZED_ENDPOINT);
            if (wrapper.isExceptionEncountered()) {
                throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, wrapper.toString(), wrapper.getStatus());
            } // something happened someplace else and the exception was handled.
            String content = wrapper.toString();
            // issue now is that the nonce was registered in the init servlet (as it should be for OA1)
            // and now it will be rejected ever more.
            JSONObject j = JSONObject.fromObject(content);
            String code = j.get("code").toString();
            String state = j.get("state").toString();
            request.setAttribute("code", code);
            request.setAttribute("state", state);
        }
        super.doIt(request, response);

    }


    protected void handleClaims(HttpServletRequest httpServletRequest,
                                 OA2ServiceTransaction transaction) throws Throwable {

         // Need to find the sources
         OA2Client client = transaction.getOA2Client();
         if (client.isPublicClient()) {
             // Public clients do not get claims.
             return;
         }
         OA2SE oa2se = (OA2SE) getServiceEnvironment();
         // set up functor factory with no claims since we have none yet.
 //        Map<String, Object> claims = new HashMap<>();
         UserInfo userInfo = new UserInfo();

         if (oa2se.getClaimSource().isEnabled()) {
             // allow the server to pre-populate the claims. This invokes the global claims handler for the server
             // to allow, e.g. pulling user information out of HTTp headers.
             oa2se.getClaimSource().process(userInfo, httpServletRequest, transaction);
         }
         if (client.getConfig() == null || client.getConfig().isEmpty()) {
             // no configuration for this client means do nothing here.
             return;
         }
         // so this client has a specific configuration that is to be invoked.
         OA2FunctorFactory functorFactory = new OA2FunctorFactory(userInfo.getMap());
         OA2ClientConfigurationFactory<OA2ClientConfiguration> ff = new OA2ClientConfigurationFactory(functorFactory);

         OA2ClientConfiguration oa2CC = ff.newInstance(client.getConfig());
         oa2CC.executeRuntime();
         FlowStates flowStates = new FlowStates(oa2CC.getRuntime().getFunctorMap());
         // save everything up to this point since there are no guarantees that processing will continue.
         getTransactionStore().save(transaction);
         if (flowStates.getClaims) {
             ff.createClaimSource(oa2CC,client.getConfig());
             // the runtime forbids processing claims for this request, so exit
             List<ClaimSource> claimsSources = oa2CC.getClaimSource();
             if (oa2CC.hasClaimSource()) {
                 // so there is
                 for (int i = 0; i < claimsSources.size(); i++) {
                     claimsSources.get(i).process(userInfo, httpServletRequest, transaction);
                     System.err.println(userInfo.getMap());
                 }
             }
             if (oa2CC.hasClaimsProcessing()) {
                 ff.setupClaimsProcessing(oa2CC, client.getConfig());
                 oa2CC.executeProcessing();
             }
         }
         // Now we have to set up the claims sources and process the results

         // update everything
         JSONObject states = new JSONObject();
         states.put("state", "state object for id=" + transaction.getIdentifier());
         states.put("flowState", flowStates.toJSON().toString());
         JSONObject jsonClaims = new JSONObject();
         jsonClaims.putAll(userInfo.getMap());
         states.put("claims", jsonClaims.toString());
         transaction.setState(states);
     }
    @Override
    public void prepare(PresentableState state) throws Throwable {
        super.prepare(state);
        if (state.getState() == AUTHORIZATION_ACTION_START) {
            state.getRequest().setAttribute(AUTHORIZATION_REFRESH_TOKEN_LIFETIME_KEY, AUTHORIZATION_REFRESH_TOKEN_LIFETIME_KEY);
        }
        if (state.getState() == AUTHORIZATION_ACTION_OK) {
            AuthorizedState authorizedState = (AuthorizedState) state;
            ((OA2ServiceTransaction) authorizedState.getTransaction()).setAuthTime(new Date());

        }
    }


    @Override
    public void present(PresentableState state) throws Throwable {
        super.present(state);

    }

    @Override
    protected void createRedirect(HttpServletRequest request, HttpServletResponse response, ServiceTransaction trans) throws Throwable {
        String rawrtl = request.getParameter(AUTHORIZATION_REFRESH_TOKEN_LIFETIME_KEY);
        OA2ServiceTransaction st2 = (OA2ServiceTransaction) trans;
        try {
            if (rawrtl != null) {
                st2.setRefreshTokenLifetime(Long.parseLong(rawrtl) * 1000);
            }
        } catch (Throwable t) {
            st2.setRefreshTokenLifetime(0L);
        }
        super.createRedirect(request, response, trans);
        // At this point, all authentication has been done, everything is set up and th enet stop in the flow is the
        // redirect back to the client.
        OA2ClaimsUtil claimsUtil = new OA2ClaimsUtil((OA2SE) getServiceEnvironment(), st2);
        claimsUtil.createClaims(request);
    }

    @Override
    public String createCallback(ServiceTransaction trans, Map<String, String> params) {

        String cb = trans.getCallback().toString();
        if(!cb.toLowerCase().startsWith("https:")){
            throw new GeneralException("Error: Unsupported callback protocol for \"" + cb + "\". Must be https");
        }
        String idStr = trans.getIdentifierString();
        try {
            cb = cb + (cb.indexOf("?") == -1 ? "?" : "&") + OA2Constants.AUTHORIZATION_CODE + "=" + URLEncoder.encode(idStr, "UTF-8");
            if (params.containsKey(OA2Constants.STATE)) {
                cb = cb + "&" + OA2Constants.STATE + "=" + URLEncoder.encode(params.get(OA2Constants.STATE), "UTF-8");
            }

        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return cb;
    }

    /**
     * Spec says we do the cert request in the authorization servlet.
     *
     * @param trans
     * @param statusString
     * @throws Throwable
     */
    @Override
    protected void doRealCertRequest(ServiceTransaction trans, String statusString) throws Throwable {
        // do nix here in this protocol.
    }



    @Override
    protected void setupMPConnection(ServiceTransaction trans, String username, String password) throws GeneralSecurityException {
        if (((OA2SE) getServiceEnvironment()).isTwoFactorSupportEnabled()) {
         // Stash username and password in an bogus MyProxy logon instance.
            MyMyProxyLogon myProxyLogon = new MyMyProxyLogon();
            myProxyLogon.setUsername(username);
            myProxyLogon.setPassphrase(password);
            MyProxyConnectable mpc = new MPSingleConnectionProvider.MyProxyLogonConnection(myProxyLogon);
            mpc.setIdentifier(trans.getIdentifier());
            getMyproxyConnectionCache().add(mpc);
        }else{
            createMPConnection(trans.getIdentifier(), username, password, trans.getLifetime());
            if (hasMPConnection(trans.getIdentifier())) {
                getMPConnection(trans.getIdentifier()).close();
            }
        }
    }
}

