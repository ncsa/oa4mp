package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.JWTUtil2;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.PayloadHandler;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.PayloadHandlerConfig;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse;
import net.sf.json.JSONObject;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

import static edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse.RC_NOT_RUN;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/21/20 at  5:00 PM
 */
public abstract class AbstractPayloadHandler implements PayloadHandler {
    protected OA2ServiceTransaction transaction;
    protected OA2SE oa2se;
    protected JSONObject claims;
    protected HttpServletRequest request;

    public PayloadHandlerConfigImpl getPhCfg() {
        return phCfg;
    }


    PayloadHandlerConfigImpl phCfg;

    /**
     * Create the instance for the authorization phase, while there is an {@link HttpServletRequest} with possible
     * headers that need to be processed.
     *
     * @param payloadHandlerConfig
     */

    public AbstractPayloadHandler(PayloadHandlerConfigImpl payloadHandlerConfig) {
        phCfg = payloadHandlerConfig;
        oa2se = phCfg.getOa2se();
        transaction = phCfg.getTransaction();
        request = phCfg.getRequest();
        ServletDebugUtil.trace(this, "payload handler cfg=" + phCfg);
        ServletDebugUtil.trace(this, "transaction =" + transaction);
        ServletDebugUtil.trace(this, "has OA2SE? " + (oa2se != null));
        //   claims = new JSONObject();
        claims = null; // use lazy initialization
    }

    @Override
    public JSONObject getClaims() {
        if (claims == null) {
            claims = transaction.getUserMetaData();
        }
        return claims;
    }

    public void setClaims(JSONObject claims) {
        transaction.setUserMetaData(claims);
        this.claims = claims;
    }

    public void setExtendedAttributes(JSONObject extendedAttributes) {
        this.extendedAttributes = extendedAttributes;
    }

    JSONObject extendedAttributes = null;

    /**
     * Gets the extended attributes from the current transaction. See {@link OA2ServiceTransaction#getExtendedAttributes()}
     * for more.
     *
     * @return
     */
    public JSONObject getExtendedAttributes() {
        if (extendedAttributes == null) {
            extendedAttributes = transaction.getExtendedAttributes();
        }
        return extendedAttributes;
    }

    protected boolean isEmpty(String x) {
        return x == null || 0 == x.length();
    }

    @Override
    public JSONObject execute(ClaimSource source, JSONObject claims) throws Throwable {
        // If this is disabled, return the claims unaltered -- do not execute.
        if (!source.isEnabled()) {
            return claims;
        }
        if (!source.isEnabled()) {
            return claims; // do nothing if the source is enabled.
        }
        // Fix for CIL-693:
        // Inject current state here!
        if (source instanceof BasicClaimsSourceImpl) {
            ((BasicClaimsSourceImpl) source).setOa2SE(oa2se);
        }
        // For those handlers that may require the http servlet request, pass it along.
        if (request == null) {
            return source.process(claims, transaction);
        } else {
            return source.process(claims, request, transaction);
        }
    }

    @Override
    public void refresh() throws Throwable {

    }

    @Override
    public void setPhCfg(PayloadHandlerConfig phCfg) {
        this.phCfg = (PayloadHandlerConfigImpl) phCfg;
    }

    @Override
    public String getToken(JSONWebKey key) {
        if (getClaims() == null || getClaims().isEmpty()) {
            return "";
        }
        try {
            return JWTUtil2.createJWT(getClaims(), key);
        } catch (Throwable e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }
            throw new GeneralException("Could not create signed token", e);
        }
    }

    public void setResponseCode(int responseCode) {
        this.responseCode = responseCode;
    }

    public int getResponseCode() {
        return responseCode;
    }

    int responseCode = RC_NOT_RUN;

    @Override
    public void handleResponse(ScriptRunResponse resp) throws Throwable {
        responseCode = resp.getReturnCode();
    }

    /**
     * A utility to take a list and convert it to a blank delimited string.
     * This is returned by any number of handlers. Note that objects
     *
     * @param list
     * @return
     */
    protected String listToString(List list) {
        String requestedScopes = "";
        if (list == null | list.isEmpty()) {
            return requestedScopes;
        }
        boolean firstPass = true;
        for (Object x : list) {
            if (x == null) {
                continue;
            }
            if (firstPass) {
                firstPass = false;
                requestedScopes = x.toString();
            } else {
                requestedScopes = requestedScopes + " " + x.toString();
            }
        }
        return requestedScopes;
    }


    @Override
    public boolean hasScript() {
        if (getPhCfg() == null) {
            return false;
        }
        return getPhCfg().getScriptSet() != null && !getPhCfg().getScriptSet().isEmpty();
    }
}
