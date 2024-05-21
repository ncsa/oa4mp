package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2HeaderUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.transactions.OA2ServiceTransaction;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.TokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.jwt.PayloadHandler;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.jwt.PayloadHandlerConfig;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunRequest;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse;
import net.sf.json.JSONObject;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse.RC_NOT_RUN;
import static edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse.RC_OK;
import static edu.uiuc.ncsa.security.util.scripting.ScriptingConstants.*;

/**
 * This is a handler for all scripts that the user may set in the configuration. These
 * scripts are run before any that the client defines so this is the first
 * handler if present. Mostly this is vessel for conveying the scripts.
 * <p>Created by Jeff Gaynor<br>
 * on 4/30/22 at  5:52 AM
 */
public class ServerQDLScriptHandler implements PayloadHandler {
    ServerQDLScriptHandlerConfig cfg;

    public ServerQDLScriptHandler(ServerQDLScriptHandlerConfig config) {
        this.cfg = config;
    }

    @Override
    public void init() throws Throwable {

    }

    @Override
    public void refresh() throws Throwable {

    }

    /**
     * For the server script, request everything. This allows for complete access
     * as needed, so if a script, e.g., wants to set up all values
     * in the pre_auth stage, it can do it once and be done, rather than
     * require it to set it in increments.
     *
     * @param req
     * @throws Throwable
     */
    @Override
    public void addRequestState(ScriptRunRequest req) throws Throwable {
        req.getArgs().put(SRE_REQ_CLAIM_SOURCES, getSources()); // so its a map
        req.getArgs().put(SRE_REQ_CLAIMS, getUserMetaData());
        req.getArgs().put(SRE_REQ_ACCESS_TOKEN, getAtData());
        req.getArgs().put(SRE_REQ_REFRESH_TOKEN, getRTData());
        if (getPhCfg().request != null) {
            JSONObject json  = OA2HeaderUtils.headerToJSON(getPhCfg().request,
                    Arrays.asList(new String[]{"authorization", "cookie", "host"}));
            if (!json.isEmpty()) {
                req.getArgs().put(SRE_REQ_AUTH_HEADERS, json);
            }
        }
    }


    public JSONObject getRTData() {
        return cfg.transaction.getRTData();
    }

    public void setRTData(JSONObject rtData) {
        cfg.transaction.setRTData(rtData);
    }


    @Override
    public void checkClaims() throws Throwable {

    }

    List<ClaimSource> sources = new ArrayList<>();

    /**
     * Must be empty since there are no sources
     *
     * @return
     * @throws Throwable
     */
    @Override
    public List<ClaimSource> getSources() throws Throwable {
        return cfg.transaction.getClaimSources(cfg.oa2SE);
    }

    @Override
    public JSONObject execute(ClaimSource source, JSONObject claims) throws Throwable {
        if (!source.isEnabled()) {
            return claims;
        }
        if (!source.isEnabled()) {
            return claims; // do nothing if the source is enabled.
        }
        // Fix for CIL-693:
        // Inject current state here!
        if (source instanceof BasicClaimsSourceImpl) {
            ((BasicClaimsSourceImpl) source).setOa2SE(cfg.oa2SE);
        }
        // For those handlers that may require the http servlet request, pass it along.
        if (cfg.request == null) {
            return source.process(claims, cfg.transaction);
        } else {
            return source.process(claims, cfg.request, cfg.transaction);
        }
    }

    @Override
    public void finish(String execPhase) throws Throwable {

    }

    @Override
    public void saveState(String execPhase) throws Throwable {

    }


    public JSONObject getUserMetaData() {
        return cfg.transaction.getUserMetaData();
    }

    public void setClaims(JSONObject claims) {
        cfg.transaction.setUserMetaData(claims);
    }


    /**
     * Gets the extended attributes from the current transaction. See {@link OA2ServiceTransaction#getExtendedAttributes()}
     * for more.
     *
     * @return
     */
    public JSONObject getExtendedAttributes() {
        return cfg.transaction.getExtendedAttributes();
    }

    public void setExtendedAttributes(JSONObject extendedAttributes) {
        cfg.transaction.setExtendedAttributes(extendedAttributes);
    }


    @Override
    public void setAccountingInformation() {

    }

    @Override
    public void refreshAccountingInformation() {

    }

    @Override
    public ServerQDLScriptHandlerConfig getPhCfg() {
        return cfg;
    }

    @Override
    public void setPhCfg(PayloadHandlerConfig phCfg) {
        this.cfg = (ServerQDLScriptHandlerConfig) phCfg;
    }

    @Override
    public boolean hasScript() {
        return cfg.oa2SE.getQDLEnvironment().hasServerScripts();
    }

/*    public String getToken(JSONWebKey key) {
        throw new NotImplementedException("no tokens from server script handler");
    }*/

    public void setResponseCode(int responseCode) {
        this.responseCode = responseCode;
    }

    public int getResponseCode() {
        return responseCode;
    }

    int responseCode = RC_NOT_RUN;

    public JSONObject getAtData() {
        return cfg.transaction.getATData();
    }


    public void setAtData(JSONObject atData) {
        cfg.transaction.setATData(atData);
    }


    @Override
    public void handleResponse(ScriptRunResponse resp) throws Throwable {
        responseCode = resp.getReturnCode();
        switch (resp.getReturnCode()) {
            case RC_OK:
                // Note that the returned values from a script are very unlikely to be the same object we sent
                // even if the contents are the same, since scripts may have to change these in to other data structures
                // to make them accessible to their machinery, then convert them back.
                setClaims((JSONObject) resp.getReturnedValues().get(SRE_REQ_CLAIMS));
                setAtData((JSONObject) resp.getReturnedValues().get(SRE_REQ_ACCESS_TOKEN));
                setRTData((JSONObject) resp.getReturnedValues().get(SRE_REQ_REFRESH_TOKEN));
                resp.getReturnedValues().get(SRE_REQ_CLAIM_SOURCES);
                return;
            case RC_NOT_RUN:
                return;
        }
    }

    @Override
    public JSONObject getPayload() {
        throw new NotImplementedException("No single payload in QDL Script Handler");
    }

    @Override
    public void setPayload(JSONObject payload) {
        throw new NotImplementedException("No single payload in QDL Script Handler");
    }

    @Override
    public TokenImpl getSignedPayload(JSONWebKey key) {
        throw new NotImplementedException("No single payload in QDL Script Handler");
    }

    @Override
    public TokenImpl getSignedPayload(JSONWebKey key, String headerType) {
        throw new NotImplementedException("No single payload in QDL Script Handler");
    }
}
