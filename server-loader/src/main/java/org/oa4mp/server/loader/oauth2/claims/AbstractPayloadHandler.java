package org.oa4mp.server.loader.oauth2.claims;

import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.loader.oauth2.storage.transactions.OA2ServiceTransaction;
import org.oa4mp.server.loader.oauth2.storage.tx.TXRecord;
import org.oa4mp.server.api.storage.servlet.OA4MPServlet;
import org.oa4mp.delegation.server.OA2Scopes;
import org.oa4mp.delegation.server.jwt.PayloadHandler;
import org.oa4mp.delegation.server.jwt.PayloadHandlerConfig;
import org.oa4mp.delegation.server.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.core.util.Iso8601;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import edu.uiuc.ncsa.security.util.configuration.TemplateUtil;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

import static edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse.RC_NOT_RUN;
import static org.oa4mp.delegation.server.server.claims.OA2Claims.*;


/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/21/20 at  5:00 PM
 */
public abstract class AbstractPayloadHandler implements PayloadHandler, OA2Scopes {
    protected OA2ServiceTransaction transaction;
    protected OA2SE oa2se;
    protected HttpServletRequest request;
    protected OA2Client client;

    public PayloadHandlerConfigImpl getPhCfg() {
        return phCfg;
    }


    PayloadHandlerConfigImpl phCfg;

    public boolean hasTXRecord() {
        return getPhCfg().hasTXRecord();
    }

    public TXRecord getTXRecord() {
        return getPhCfg().getTxRecord();
    }

    /**
     * Create the instance for the authorization phase, while there is an {@link HttpServletRequest} with possible
     * headers that need to be processed.
     *
     * @param payloadHandlerConfig
     */
    public AbstractPayloadHandler(PayloadHandlerConfigImpl payloadHandlerConfig) {
        phCfg = payloadHandlerConfig;
        oa2se = phCfg.getOa2se();
        client = phCfg.getClient();
        transaction = phCfg.getTransaction();
        request = phCfg.getRequest();
        ServletDebugUtil.trace(this, "payload handler cfg=" + phCfg);
        ServletDebugUtil.trace(this, "transaction =" + transaction.summary());
        ServletDebugUtil.trace(this, "has OA2SE? " + (oa2se != null));
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
        return transaction.getExtendedAttributes();
    }

    protected boolean isEmpty(String x) {
        return x == null || 0 == x.length();
    }

    @Override
    public JSONObject execute(ClaimSource source, JSONObject claims) throws Throwable {
        // If this is disabled, return the claims unaltered -- do not execute.
        MetaDebugUtil debugger = OA4MPServlet.createDebugger(transaction.getClient());

        if (!source.isEnabled()) {
            debugger.trace(this, "source disabled");
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


/*
    @Override
abstract   public String getToken(JSONWebKey key)
    {
        if (getUserMetaData() == null || getUserMetaData().isEmpty()) {
            return "";
        }
        try {
            return MyOtherJWTUtil2.createJWT(getUserMetaData(), key);
        } catch (Throwable e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }
            throw new GeneralException("Could not create signed token", e);
        }
    }
*/

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

    /**
     * Used by access tokens and refresh tokens. This allows for certain substitutions for various server
     * variables. So e.g. if a template is of the form
     * <pre>
     *     read:/path/to/${sub}
     * </pre>
     * then the value of the sub claim will be used in place of ${sub}.
     * <p>
     *     See the <b>Server Constants</b> section in the <a href="https://oa4mp.org/pdf/token_handler_configuration.pdf">token handler configuration</a>.
     * </p>
     *
     * @param targetClaims
     */
    protected void doServerVariables(JSONObject targetClaims, JSONObject userMetaData) {
        JSONObject serverVariableTemplates = new JSONObject();
        // Allow for substitutions in audience, subject, issuer and resource
        if (userMetaData != null) {
            serverVariableTemplates.putAll(userMetaData);
        }
        long now = System.currentTimeMillis();
        serverVariableTemplates.put("client_id", getPhCfg().getTransaction().getClient().getIdentifierString());
        serverVariableTemplates.put("host", getPhCfg().getOa2se().getServiceAddress().toString());
        serverVariableTemplates.put("now", now);
        serverVariableTemplates.put("now_iso", Iso8601.date2String(now));
        serverVariableTemplates.put("now_sec", Iso8601.date2String(now / 1000));
        if (serverVariableTemplates.containsKey("eppn")) {
            serverVariableTemplates.put("eppn_2", serverVariableTemplates.getString("eppn").substring(0, serverVariableTemplates.getString("eppn").indexOf("@")));
        }
        doSubstitution(SUBJECT, targetClaims, serverVariableTemplates);
        doSubstitution(RESOURCE, targetClaims, serverVariableTemplates);
        doSubstitution(ISSUER, targetClaims, serverVariableTemplates);
        doSubstitution(AUDIENCE, targetClaims, serverVariableTemplates);
    }

    /**
     * Do template substitutions for subject, audience, resource and issuer.
     *
     * @param key
     * @param targetClaims
     * @param x
     */
    protected void doSubstitution(String key, JSONObject targetClaims, JSONObject x) {
        if (!targetClaims.containsKey(key)) {
            return;
        }
        Object obj = targetClaims.getString(key);
        if (obj instanceof JSONArray) {
            JSONArray jsonArray = (JSONArray) obj;
            for (int i = 0; i < jsonArray.size(); i++) {
                Object y = jsonArray.get(i);
                if (y instanceof String) {
                    String s = (String) obj;
                    String newSubject = TemplateUtil.replaceAll(s, x);
                    jsonArray.set(i, newSubject);
                }
            }
            targetClaims.put(key, jsonArray);
        } else {
            if (obj instanceof String) {
                String s = (String) obj;
                String newSubject = TemplateUtil.replaceAll(s, x);
                targetClaims.put(key, newSubject);
            }
        }
    }

    @Override
    public void saveState(String execPhase) throws Throwable {
        if(hasTXRecord()) {
            getTXRecord().setToken(getPayload());
        }
    }


    @Override
    public void setPayload(JSONObject payload) {
        this.payload = payload;
    }

    protected JSONObject payload;
}
