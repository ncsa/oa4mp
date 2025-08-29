package org.oa4mp.server.proxy;


import edu.uiuc.ncsa.security.servlet.HeaderUtils;
import edu.uiuc.ncsa.security.servlet.PresentableState;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import net.sf.json.JSONObject;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.http.HttpStatus;
import org.oa4mp.delegation.server.OA2Constants;
import org.oa4mp.delegation.server.OA2Errors;
import org.oa4mp.delegation.server.OA2GeneralError;
import org.oa4mp.delegation.server.ServiceTransaction;
import org.oa4mp.delegation.server.jwt.HandlerRunner;
import org.oa4mp.server.api.storage.servlet.AbstractAuthenticationServlet;
import org.oa4mp.server.api.storage.servlet.OA4MPServlet;
import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.servlet.OA2AuthorizedServletUtil;
import org.oa4mp.server.loader.oauth2.servlet.OA2ClientUtils;
import org.oa4mp.server.loader.oauth2.state.ScriptRuntimeEngineFactory;
import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.loader.oauth2.storage.transactions.OA2ServiceTransaction;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

import static org.oa4mp.delegation.server.OA2Constants.AUTHORIZATION_CODE;
import static org.oa4mp.delegation.server.OA2Constants.AUTHORIZATION_STATE;


/**
 * This is deployed as the /authorize endpoint.
 * <p>Created by Jeff Gaynor<br>
 * on 2/7/14 at  11:44 AM
 */
public class OA2AuthenticationServer extends AbstractAuthenticationServlet {

    @Override
    protected void createRedirectInit(ServiceTransaction trans, String userName, String password) {

    }

    public String AUTHORIZATION_REFRESH_TOKEN_LIFETIME_KEY = "AuthRTL";


    /**
     * Turn the scopes into a string. Since the user may send the same scope repetedly
     * @param t
     * @return
     */
    protected static String scopesToString(OA2ServiceTransaction t) {
        Collection<String> scopes = t.getScopes();

        return scopesToString(scopes);
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
        ServletDebugUtil.printAllParameters(getClass(), request,true);
        Map<String, String> map = getFirstParameters(request);
        if(map.containsKey("action") && map.get("action").equals("ok")){
            // If authZ in progress, send to consent page here.
            super.doIt(request, response);
            logOK(request); //CIL-1722
            return;
        }
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
        init.doDelegation(request, wrapper); // creates transaction, writes it to wrapper
        if (wrapper.isExceptionEncountered()) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, wrapper.toString(), wrapper.getStatus(),
                    HeaderUtils.getFirstParameterValue(request, OA2Constants.STATE));
        } // something happened someplace else and the exception was handled.
        String content = wrapper.toString();
        // issue now is that the nonce was registered in the init servlet (as it should be for OA1)
        // and now it will be rejected ever more.
        JSONObject j = JSONObject.fromObject(content);
        // Fix RCAuth https://github.com/rcauth-eu/OA4MP/commit/d052e0a64fe527adb7636fe146179ffbac472380
        // Fix https://github.com/ncsa/oa4mp/pull/237, https://github.com/ncsa/oa4mp/issues/238
        if(j.containsKey(AUTHORIZATION_CODE)){
            request.setAttribute(AUTHORIZATION_CODE, j.get(AUTHORIZATION_CODE).toString());
        }
        if(j.containsKey(AUTHORIZATION_STATE)) {
            request.setAttribute(AUTHORIZATION_STATE, j.get(AUTHORIZATION_STATE).toString());
        }

        super.doIt(request, response);
        logOK(request); //CIL-1722
    }


    @Override
    public void prepare(PresentableState state) throws Throwable {
        super.prepare(state);
        if (state.getState() == AbstractAuthenticationServlet.AUTHORIZATION_ACTION_START) {
            state.getRequest().setAttribute(AUTHORIZATION_REFRESH_TOKEN_LIFETIME_KEY, AUTHORIZATION_REFRESH_TOKEN_LIFETIME_KEY);
        }
        if (state.getState() == AbstractAuthenticationServlet.AUTHORIZATION_ACTION_OK) {
            AuthorizedState authorizedState = (AuthorizedState) state;
            OA2ServiceTransaction st = (OA2ServiceTransaction)authorizedState.getTransaction();
            Date now = new Date();
            st.setAuthTime(now);
            st.getClient().setLastAccessed(now);
        }
    }


    @Override
    protected void createRedirect(HttpServletRequest request, HttpServletResponse response, ServiceTransaction trans) throws Throwable {
        String rawrtl = request.getParameter(AUTHORIZATION_REFRESH_TOKEN_LIFETIME_KEY);
        OA2SE oa2SE = (OA2SE) OA4MPServlet.getServiceEnvironment();

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
        HandlerRunner handlerRunner = new HandlerRunner(st2, ScriptRuntimeEngineFactory.createRTE(oa2SE, st2, resolvedClient.getConfig()));
        OA2ClientUtils.setupHandlers(handlerRunner, oa2SE, st2, resolvedClient, request);
        handlerRunner.doAuthClaims();

        getTransactionStore().save(st2);
    }

    @Override
    public String createCallback(ServiceTransaction trans, Map<String, String> params) {
        return OA2AuthorizedServletUtil.createCallback(trans, params);
       /* String cb = trans.getCallback().toString();
        OA2ServiceTransaction st = (OA2ServiceTransaction) trans;
        *//*
        CIL-545: The checking for valid callbacks is done at registration time. No checking should be done
        any place else since we must support a much wider range of these (e.g. for mobile devices). 
         *//*

        String idStr = st.getIdentifierString();
        // Fixes GitHub OA4MP issue 5, support multiple response modes.
        String responseDelimiter = "?"; // default
        if (st.hasResponseMode()) {
            if (st.getResponseMode().equals(OA2Constants.RESPONSE_MODE_FRAGMENT)) {
                responseDelimiter = "#";
            }
        }
        try {
            cb = cb + (cb.indexOf(responseDelimiter) == -1 ? responseDelimiter : "&") + AUTHORIZATION_CODE + "=" + TokenUtils.b32EncodeToken(idStr);
            if (params.containsKey(OA2Constants.STATE)) {
                cb = cb + "&" + OA2Constants.STATE + "=" + URLEncoder.encode(params.get(OA2Constants.STATE), "UTF-8");
            }
            // Fix https://github.com/ncsa/oa4mp/issues/214 RFC 9207 support
            if(((OA2ServiceTransaction) trans).getUserMetaData().containsKey(OA2Claims.ISSUER)){
                cb = cb + (cb.indexOf(responseDelimiter) == -1 ? responseDelimiter : "&")  + OA2Claims.ISSUER + "=" + st.getUserMetaData().get(OA2Claims.ISSUER);
            }

        } catch (UnsupportedEncodingException e) {
            e.printStackTrace(); // now way this can happen, but if it does, we want to know about it.
        }
        ((OA2ServiceTransaction) trans).setCreatedCallback(cb);
        return cb;*/
    }

    @Override
    protected void doProxy(AuthorizedState state) throws Throwable {
        ProxyUtils.doProxy((OA2SE) OA4MPServlet.getServiceEnvironment(), state);
    }
}

