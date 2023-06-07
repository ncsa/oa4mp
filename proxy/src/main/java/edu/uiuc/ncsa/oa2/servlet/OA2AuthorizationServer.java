package edu.uiuc.ncsa.oa2.servlet;


import edu.uiuc.ncsa.myproxy.MPSingleConnectionProvider;
import edu.uiuc.ncsa.myproxy.MyProxyConnectable;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2AuthorizedServletUtil;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2ClientUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.ScriptRuntimeEngineFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.transactions.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractAuthorizationServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AccessToken;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.TokenUtils;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Constants;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Errors;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2GeneralError;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.jwt.JWTRunner;
import edu.uiuc.ncsa.oa4mp.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.servlet.PresentableState;
import net.sf.json.JSONObject;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.GeneralSecurityException;
import java.util.Collection;
import java.util.Date;
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

    protected static String scopesToString(OA2ServiceTransaction t) {
        return scopesToString(t.getScopes());
    }

    protected static String scopesToString(Collection<String> listOfScopes) {
        String scopeString = "";
        for (String x : listOfScopes) {
            scopeString = scopeString + x + " ";
        }
        return scopeString.trim(); // don't return trailing blank(s)
    }

    @Override
    protected void setClientRequestAttributes(AuthorizedState aState) {
        super.setClientRequestAttributes(aState);
        HttpServletRequest request = aState.getRequest();

        OA2ServiceTransaction t = (OA2ServiceTransaction) aState.getTransaction();
        request.setAttribute("clientScopes", StringEscapeUtils.escapeHtml(scopesToString(t)));

    }


    protected OA2AuthorizedServletUtil getInitUtil() {
        return new OA2AuthorizedServletUtil(this);
    }

    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {

        Map<String, String> map = getFirstParameters(request);

        if (!map.containsKey(OA2Constants.RESPONSE_TYPE)) {
            // As per both OIDC and OAuth 2 spec., this is required. OIDC compliance requires state is returned.
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                    "missing response_type",
                    HttpStatus.SC_BAD_REQUEST,
                    (map.containsKey(OA2Constants.STATE) ? map.get(OA2Constants.STATE) : ""));
        }
        // Means this is an initial request. Pass it along to the init util to
        // unscramble it.
        MyHttpServletResponseWrapper wrapper = new MyHttpServletResponseWrapper(response);
        OA2AuthorizedServletUtil init = getInitUtil();
//              JSPUtil.fwd(request, wrapper, AUTHORIZED_ENDPOINT);
        init.doDelegation(request, wrapper);
        if (wrapper.isExceptionEncountered()) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, wrapper.toString(), wrapper.getStatus(),
                    getFirstParameterValue(request, OA2Constants.STATE));
        } // something happened someplace else and the exception was handled.
        String content = wrapper.toString();
        // issue now is that the nonce was registered in the init servlet (as it should be for OA1)
        // and now it will be rejected ever more.
        JSONObject j = JSONObject.fromObject(content);
        String code = j.get("code").toString();
        String state = j.get("state").toString();
        // Fix RCAuth https://github.com/rcauth-eu/OA4MP/commit/d052e0a64fe527adb7636fe146179ffbac472380
        if (code != null) {
            request.setAttribute("code", code);
        }
        if (state != null) {
            request.setAttribute("state", state);
        }
        super.doIt(request, response);
        logOK(request); //CIL-1722
    }


    @Override
    public void prepare(PresentableState state) throws Throwable {
        super.prepare(state);
        if (state.getState() == AbstractAuthorizationServlet.AUTHORIZATION_ACTION_START) {
            state.getRequest().setAttribute(AUTHORIZATION_REFRESH_TOKEN_LIFETIME_KEY, AUTHORIZATION_REFRESH_TOKEN_LIFETIME_KEY);
        }
        if (state.getState() == AbstractAuthorizationServlet.AUTHORIZATION_ACTION_OK) {
            AuthorizedState authorizedState = (AuthorizedState) state;
            ((OA2ServiceTransaction) authorizedState.getTransaction()).setAuthTime(new Date());
        }
    }


    @Override
    protected void createRedirect(HttpServletRequest request, HttpServletResponse response, ServiceTransaction trans) throws Throwable {
        String rawrtl = request.getParameter(AUTHORIZATION_REFRESH_TOKEN_LIFETIME_KEY);
        OA2SE oa2SE = (OA2SE) MyProxyDelegationServlet.getServiceEnvironment();

        OA2ServiceTransaction st2 = (OA2ServiceTransaction) trans;
        OA2Client resolvedClient = OA2ClientUtils.resolvePrototypes(oa2SE, st2.getOA2Client());
        try {
            if (rawrtl != null) {
                st2.setRefreshTokenLifetime(Long.parseLong(rawrtl) * 1000);
            }
        } catch (Throwable t) {
            st2.setRefreshTokenLifetime(0L);
        }
        super.createRedirect(request, response, trans);
        // At this point, all authentication has been done, everything is set up and the next stop in the flow is the
        // redirect back to the client.
        JWTRunner jwtRunner = new JWTRunner(st2, ScriptRuntimeEngineFactory.createRTE(oa2SE, st2, resolvedClient.getConfig()));
        OA2ClientUtils.setupHandlers(jwtRunner, oa2SE, st2, resolvedClient, request);


        jwtRunner.doAuthClaims();
        getTransactionStore().save(st2);
    }

    @Override
    public String createCallback(ServiceTransaction trans, Map<String, String> params) {
        String cb = trans.getCallback().toString();
        OA2ServiceTransaction st = (OA2ServiceTransaction) trans;
        /*
        CIL-545: The checking for valid callbacks is done at registration time. No checking should be done
        any place else since we must support a much wider range of these (e.g. for mobile devices). 
         */
     /*  This is the code that used to check that the protocol was https before creating the callback.
      if (!cb.toLowerCase().startsWith("https:")) {
            throw new GeneralException("Error: Unsupported callback protocol for \"" + cb + "\". Must be https");
        }*/

        String idStr = st.getIdentifierString();
        // Fixes GitHub OA4MP issue 5, support multiple response modes.
        String responseDelimiter = "?"; // default
        if (st.hasResponseMode()) {
            if (st.getResponseMode().equals(OA2Constants.RESPONSE_MODE_FRAGMENT)) {
                responseDelimiter = "#";
            }
        }
        try {
            cb = cb + (cb.indexOf(responseDelimiter) == -1 ? responseDelimiter : "&") + OA2Constants.AUTHORIZATION_CODE + "=" + TokenUtils.b32EncodeToken(idStr);
            if (params.containsKey(OA2Constants.STATE)) {
                cb = cb + "&" + OA2Constants.STATE + "=" + URLEncoder.encode(params.get(OA2Constants.STATE), "UTF-8");
            }

        } catch (UnsupportedEncodingException e) {
            e.printStackTrace(); // now way this can happen, but if it does, we want to know about it.
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
        if (((OA2SE) MyProxyDelegationServlet.getServiceEnvironment()).isTwoFactorSupportEnabled()) {
            // Stash username and password in an bogus MyProxy logon instance.
            MyMyProxyLogon myProxyLogon = new MyMyProxyLogon();
            myProxyLogon.setUsername(username);
            myProxyLogon.setPassphrase(password);
            MyProxyConnectable mpc = new MPSingleConnectionProvider.MyProxyLogonConnection(myProxyLogon);
            mpc.setIdentifier(trans.getIdentifier());
            MyProxyDelegationServlet.getMyproxyConnectionCache().add(mpc);
        } else {
            createMPConnection(trans.getIdentifier(), username, password, trans.getLifetime());
            if (hasMPConnection(trans.getIdentifier())) {
                getMPConnection(trans.getIdentifier()).close();
            }
        }
    }

    @Override
    protected void doProxy(AuthorizedState state) throws Throwable {
        ProxyUtils.doProxy((OA2SE) MyProxyDelegationServlet.getServiceEnvironment(), state);
    }
}

