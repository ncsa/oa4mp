package edu.uiuc.ncsa.oa4mp.delegation.oa2.jwt;

import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.OIDCServiceTransactionInterface;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.ClaimSource;
import edu.uiuc.ncsa.qdl.scripting.Scripts;
import edu.uiuc.ncsa.security.core.exceptions.IllegalAccessException;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunRequest;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse;
import edu.uiuc.ncsa.security.util.scripting.ScriptRuntimeEngine;
import net.sf.json.JSONObject;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static edu.uiuc.ncsa.security.core.util.DebugUtil.trace;
import static edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse.RC_OK;
import static edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse.RC_OK_NO_SCRIPTS;
import static edu.uiuc.ncsa.security.util.scripting.ScriptingConstants.*;

/**
 * This will create a JWT. The contract is generally that it has (multiple) {@link PayloadHandler}s
 * which process a given token. These are run at various times during execution based on the phase
 * and flow states. For various historical reasons, the JWT is referred to as "claims" and it would
 * take far too much tracking down in the code to change it.
 * <p>Created by Jeff Gaynor<br>
 * on 2/15/20 at  7:38 AM
 */
public class JWTRunner {
    OIDCServiceTransactionInterface transaction;

    public AccessTokenHandlerInterface getAccessTokenHandler() {
        return accessTokenHandler;
    }

    public void setAccessTokenHandler(AccessTokenHandlerInterface accessTokenHandler) {
        this.accessTokenHandler = accessTokenHandler;
        addHandler(accessTokenHandler);
    }

    AccessTokenHandlerInterface accessTokenHandler = null;

    public IDTokenHandlerInterface getIdTokenHandlerInterface() {
        return idTokenHandlerInterface;
    }

    public void setIdTokenHandlerInterface(IDTokenHandlerInterface idTokenHandlerInterface) {
        this.idTokenHandlerInterface = idTokenHandlerInterface;
        if (idTokenHandlerInterface instanceof PayloadHandler) {
            // These invariably are indeed payload handlers, but refactoring everything for maven module
            // visibility is a pain in the neck.
            addHandler((PayloadHandler) idTokenHandlerInterface);
        }
    }

    IDTokenHandlerInterface idTokenHandlerInterface = null;

    public boolean hasIDTokenHander() {
        return idTokenHandlerInterface != null;
    }

    public boolean hasATHandler() {
        return accessTokenHandler != null;
    }

    RefreshTokenHandlerInterface refreshTokenHandler = null;

    public void setRefreshTokenHandler(RefreshTokenHandlerInterface refreshTokenHandler) {
        this.refreshTokenHandler = refreshTokenHandler;
        addHandler(refreshTokenHandler);
    }

    public RefreshTokenHandlerInterface getRefreshTokenHandler() {
        return refreshTokenHandler;
    }

    public boolean hasRTHandler() {
        return refreshTokenHandler != null;
    }


    public JWTRunner(OIDCServiceTransactionInterface transaction, ScriptRuntimeEngine scriptRuntimeEngine) {
        this.transaction = transaction;
        this.scriptRuntimeEngine = scriptRuntimeEngine;
    }

    List<PayloadHandler> handlers = new ArrayList<>();

    public void addHandler(PayloadHandler handler) {
        handlers.add(handler);
    }

    public void initializeHandlers() throws Throwable {
        for (PayloadHandler h : handlers) {
            DebugUtil.trace(this, "Running init for handler " + h);
            h.init();
            h.setAccountingInformation();
        }
    }

    public void doAuthClaims() throws Throwable {
        DebugUtil.trace(this, "Starting Auth claims");
        transaction.setFlowStates(new FlowStates());
        initializeHandlers();
        /*
        In point of fact init and pre-auth are redundant, however, some older
        scripting frameworks (well, functors) allowed for both since they
        did not have actual state they could manage. Since there are a lot of
        older configurations we still must support, we run both of these back to back.
        Any new scripting support should only support pre/post auth and pre/post token.
         */
        doScript(SRE_EXEC_INIT);
        doScript(SRE_PRE_AUTH);

        // now for the actual getting of the claims

        //  getFromSources(transaction.getFlowStates(), SRE_PRE_AUTH, true);

        doScript(SRE_POST_AUTH);

        for (PayloadHandler h : handlers) {
            h.saveState(SRE_POST_AUTH);
        }
    }

    public void doRefreshClaims() throws Throwable {
        doTokenClaims(true);
    }

    public void doTokenExchange() throws Throwable {
        for (PayloadHandler h : handlers) {
            h.setAccountingInformation();
        }
        doScript(SRE_PRE_EXCHANGE);

        doScript(SRE_POST_EXCHANGE);
        for (PayloadHandler h : handlers) {
            h.checkClaims();
        }

        for (PayloadHandler h : handlers) {
            h.saveState(SRE_POST_EXCHANGE);
        }

        for (PayloadHandler h : handlers) {
            h.finish(SRE_POST_EXCHANGE);
        }
    }

    public void doUserInfo() throws Throwable {
        for (PayloadHandler h : handlers) {
            h.setAccountingInformation();
        }
        doScript(SRE_PRE_USER_INFO);
        //CIL-1328 fix
        getFromSources(transaction.getFlowStates(), SRE_PRE_AUTH, false);
        doScript(SRE_POST_USER_INFO);
        for (PayloadHandler h : handlers) {
            h.checkClaims();
        }

        for (PayloadHandler h : handlers) {
            h.saveState(SRE_POST_USER_INFO);
        }

        for (PayloadHandler h : handlers) {
            h.finish(SRE_POST_USER_INFO);
        }
    }

    public void doTokenClaims() throws Throwable {
        doTokenClaims(false);
    }

    protected void doTokenClaims(boolean isRefresh) throws Throwable {
        doScript(isRefresh ? SRE_PRE_REFRESH : SRE_PRE_AT);

        getFromSources(transaction.getFlowStates(),
                isRefresh ? SRE_PRE_REFRESH : SRE_PRE_AT,
                false);
        if (isRefresh) {
            for (PayloadHandler h : handlers) {
                h.setAccountingInformation();
            }
        }
        doScript(isRefresh ? SRE_POST_REFRESH : SRE_POST_AT);

        for (PayloadHandler h : handlers) {
            h.checkClaims();
        }

        for (PayloadHandler h : handlers) {
            h.saveState(isRefresh ? SRE_POST_REFRESH : SRE_POST_AT);
        }

        for (PayloadHandler h : handlers) {
            h.finish(isRefresh ? SRE_POST_REFRESH : SRE_POST_AT);
        }
    }

    /**
     * Get the claims sources for the ID token. This is needed only if the handler will attempt to get
     * claims at some point.
     *
     * @param flowStates
     * @param checkAuthClaims
     * @throws Throwable
     * @deprecated This should go away at some point since it has to loop over handler and basically ignores how the system works.
     */
    protected void getFromSources(FlowStates flowStates,
                                  String execPhase,
                                  boolean checkAuthClaims) throws Throwable {
        JSONObject claims = getIdTokenHandlerInterface().getUserMetaData();
        for (PayloadHandler h : handlers) {
            if (!h.getSources().isEmpty()) {
                // so there is
                for (int i = 0; i < h.getSources().size(); i++) {
                    ClaimSource claimSource = h.getSources().get(i);
                    boolean isRunAtAuthz;
                    if (checkAuthClaims) {
                        isRunAtAuthz = claimSource.isRunAtAuthorization();
                    } else {
                        isRunAtAuthz = !claimSource.isRunAtAuthorization();
                    }
                    if (isRunAtAuthz) {
                        DebugUtil.trace(this, "executing get claims");
                        claims = h.execute(claimSource, claims);
                        //claimSource.process(claims, request, transaction);

                        // keep this in case this was set earlier.
                        if (!flowStates.acceptRequests) {
                            // This practically means that the come situation has arisen whereby the user is
                            // immediately banned from access -- e.g. they were found to be on a blacklist.
                            //throw new IllegalAccessException(OA2Errors.ACCESS_DENIED, "access denied", null, HttpStatus.SC_UNAUTHORIZED);
                            throw new IllegalAccessException();
                        }
                        h.finish(execPhase);
                    }

                    trace(this, "user info for claim source #" + claimSource + " = " + claims.toString(1));
                }
            }
/*
            if (claims != null) {
                // make sure that chained claims get stashed if there are any.
                // In functors it might not get set right, so do it here and be sure.
                transaction.setUserMetaData(claims);
            }
*/
        }
        for (PayloadHandler h : handlers) {
            if (h instanceof IDTokenHandlerInterface) {
                ((IDTokenHandlerInterface) h).setUserMetaData(claims);
            }
        }
    }

    public ScriptRuntimeEngine getScriptRuntimeEngine() {
        if (scriptRuntimeEngine == null) {
            //scriptRuntimeEngine = ScriptRuntimeEngineFactory.createRTE(getOA2Client().getConfig());
        }
        return scriptRuntimeEngine;
    }


    ScriptRuntimeEngine scriptRuntimeEngine = null;

    /**
     * creates new {@link ScriptRunRequest} with the basic information <b>from the transaction</b>.
     * Anything specific to the handler needs to be added in the {@link PayloadHandler#addRequestState(ScriptRunRequest)}.
     * This sends along the current claims, scopes
     * flow states and claim sources then harvests them <i>in toto</i> from the response.
     *
     * @return
     */
    protected ScriptRunRequest newSRR(OIDCServiceTransactionInterface transaction, String phase) {
        ScriptRunRequest initReq = new ScriptRunRequest() {
            HashMap<String, Object> map = new HashMap<>();
            boolean isPopulated = false;
            void populate(){
                if(isPopulated){
                    return;
                }
                if (transaction.getProxyState().containsKey("claims")) {
                    map.put(SRE_REQ_PROXY_CLAIMS, transaction.getProxyState().getJSONObject("claims"));
                } else {
                    map.put(SRE_REQ_PROXY_CLAIMS, new JSONObject());
                }
                // Any claim sources are injected by the appropriate handler since they typically
                // require a great deal of state that is not available yet.
                map.put(SRE_REQ_SCOPES, transaction.getScopes());
                map.put(SRE_REQ_AUDIENCE, transaction.getAudience());
                map.put(SRE_REQ_EXTENDED_ATTRIBUTES, transaction.getExtendedAttributes());
                map.put(SRE_REQ_FLOW_STATES, transaction.getFlowStates()); // so its a map
                        isPopulated = true;
            }
            @Override
            public Map<String, Object> getArgs() {
                if(!isPopulated){
                    populate();
                }
                return map;
            }

            String p = phase;

            @Override
            public String getAction() {
                return p;
            }

            @Override
            public boolean returnArgs() {
                return true;
            }

            @Override
            public String getResponseArgName() {
                return "";
            }

            @Override
            public boolean hasReturnedValue() {
                return false;
            }
        };
        return initReq;
    }

    /**
     * Process the script, but the claim sources are not updated because
     * we are not interested in the claim sources, e.g. if this is
     * called after all claims sources have been processed  and the script just massages the claims or flow states.
     *
     * @param scriptRunResponse
     */

    protected void handleSREResponse(OIDCServiceTransactionInterface transaction, ScriptRunResponse scriptRunResponse) throws IOException {
        switch (scriptRunResponse.getReturnCode()) {
            case RC_OK:
                // Note that the returned values from a script are very unlikely to be the same object we sent
                // even if the contents are the same, since scripts may have to change these in to other data structures
                // to make them accessible to their machinery, then convert them back.
                transaction.setFlowStates((FlowStates) scriptRunResponse.getReturnedValues().get(SRE_REQ_FLOW_STATES));
                return;
            case ScriptRunResponse.RC_NOT_RUN:
                return;

        }

        throw new NotImplementedException("Error: other script runtime reponses not implemented yet.");
    }

    protected void doScript(String phase) throws Throwable {
        newDoScript(phase);
    }

    protected void newDoScript(String phase) throws Throwable {
        if (getScriptRuntimeEngine() == null) {
            return;
        }
        if (handlers.isEmpty()) {
            ScriptRunRequest req = newSRR(transaction, phase);

            // Functors do not have handlers, it all comes through the script engine.
            // Therefore, if this does not have handlers, try to run it as legacy code

            ScriptRunResponse resp = getScriptRuntimeEngine().run(req);
            handleSREResponse(transaction, resp);

        } else {
            // This has handlers so it new and should be run as such.
            // only try to do a handler if it has a script for this phase OR if you know it use functors.
            PayloadHandler previousHandler = null;
            for (PayloadHandler h : handlers) {
                if (h.getPhCfg().isLegacyHandler() || (h.hasScript() && h.getPhCfg().getScriptSet().get(Scripts.EXEC_PHASE, phase) != null)) {
                    ScriptRunRequest req = newSRR(transaction, phase);
                    if(previousHandler != null && previousHandler instanceof IDTokenHandlerInterface){
                        /*
                          Handlers are processed in order, IDTokenHandler, Access then refresh. UserMeta data can be updated
                          between iterations in this loop so forward the UMD on to the next handler.
                         */
                        if(h instanceof IDTokenHandlerInterface){
                            ((IDTokenHandlerInterface)h).setUserMetaData(((IDTokenHandlerInterface)previousHandler).getUserMetaData());
                        }
                    }
                    h.addRequestState(req);
                    getScriptRuntimeEngine().clearScriptSet();
                    getScriptRuntimeEngine().setScriptSet(h.getPhCfg().getScriptSet());
                    ScriptRunResponse resp = getScriptRuntimeEngine().run(req);
                    handleSREResponse(transaction, resp);
                    h.handleResponse(resp);
                    previousHandler = h;
                } else {
                    // plain handler cases -- no scripting
                    // These are executed at exactly on phase.
                    // All that has happened at this point is that they have been initialized (so config
                    // info put in place) and then we save the results of that.
                    switch (phase) {
                        case SRE_PRE_AUTH:
                        case SRE_PRE_USER_INFO:
                            // Get the sources in the pre-auth phase. This chains them together for
                            // a SINGLE handler.
                            if (h instanceof IDTokenHandlerInterface) {
                                IDTokenHandlerInterface hhh = (IDTokenHandlerInterface) h;
                                JSONObject currentUMD = hhh.getUserMetaData();
                                for (ClaimSource claimSource : h.getSources()) {
                                    currentUMD = h.execute(claimSource, currentUMD);
                                    hhh.setUserMetaData(currentUMD); // make sure it is updated!
                                }
                            }
                            break;
                        case SRE_POST_AUTH:
                            if (h instanceof IDTokenHandlerInterface) {
                                h.setResponseCode(RC_OK_NO_SCRIPTS);
                                h.finish(phase);
                                h.saveState(SRE_POST_AUTH);
                            }
                            break;
                        case SRE_POST_AT:
                        case SRE_POST_REFRESH:
                        case SRE_POST_EXCHANGE:
                            if (h instanceof AccessTokenHandlerInterface || h instanceof RefreshTokenHandlerInterface) {
                                h.setResponseCode(RC_OK_NO_SCRIPTS);
                                h.finish(phase);
                                h.saveState(SRE_POST_EXCHANGE);
                            }
                    }
                }
                // request makes copies of everything to turn in to QDL state, make it at the last second,  keep it is up to date.
            }
        }
    }

}
