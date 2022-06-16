package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.FlowStates2;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2DiscoveryServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.ScriptRuntimeEngineFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.transactions.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Scopes;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunRequest;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse;
import edu.uiuc.ncsa.security.util.scripting.ScriptRuntimeEngine;
import edu.uiuc.ncsa.security.util.scripting.ScriptingConstants;
import net.sf.json.JSONObject;
import org.apache.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.AUTHORIZATION_TIME;
import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.NONCE;
import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.*;

/**
 * This used to be the main claims processing engine until scripting was improved
 * in version 4.4.
 * If you are using it, there is probably something wrong. It is kept since there is some
 * good code in it, mostly for reference if something ever breaks, I can refer to this
 * to see if it had something better.
 * @deprecated 
 * <p>Created by Jeff Gaynor<br>
 * on 4/24/18 at  11:13 AM
 */
public class OA2ClaimsUtil implements ScriptingConstants {
    /*
    ONly enable this if you want to see everything. Lots of output.
     */
    boolean deepDebugOn = true;

    protected OA2ServiceTransaction transaction;
    OA2SE oa2se;

    public OA2ClaimsUtil(OA2SE oa2se, OA2ServiceTransaction transaction) {
        this.oa2se = oa2se;
        this.transaction = transaction;
    }

    public ScriptRuntimeEngine getScriptRuntimeEngine() {
        if (scriptRuntimeEngine == null) {
            scriptRuntimeEngine = ScriptRuntimeEngineFactory.createRTE(oa2se, transaction, getOA2Client().getConfig());
        }
        return scriptRuntimeEngine;
    }


    ScriptRuntimeEngine scriptRuntimeEngine = null;

    /**
     * <b><i>ONLY reset the accounting information (timestamps etc.) </i></b>
     *
     * @param request
     * @param claims
     * @return
     */
    public JSONObject setAccountingInformation(HttpServletRequest request, JSONObject claims) {

        dbg(this, "Starting to process basic claims");
        if (transaction.hasAuthTime()) {
            // convert the date to a time if needed.
            claims.put(AUTHORIZATION_TIME, Long.toString(transaction.getAuthTime().getTime() / 1000));
        }
        claims.put(EXPIRATION, System.currentTimeMillis() / 1000 + 15 * 60); // expiration is in SECONDS from the epoch.
        claims.put(ISSUED_AT, System.currentTimeMillis() / 1000); // issued at = current time in seconds.
        if (transaction.hasAuthTime()) {
            // convert the date to a time if needed.
            claims.put(AUTHORIZATION_TIME, Long.toString(transaction.getAuthTime().getTime() / 1000));
        }
        if (transaction.getNonce() != null && 0 < transaction.getNonce().length()) {
            claims.put(NONCE, transaction.getNonce());
        }
        return claims;
    }

    /**
     * This method puts the required information into a claims. Use this on claims again whenever a
     * request for claims is made, so the timestamps etc. are current. Some clients use this information,
     * for better for work, as accounting information on the access or refresh token and these clients
     * will break if the timestamps are not updated (e.g. kubernetes). <br/>
     * <p/>
     * Note that if you call this after processing, claim sources etc. you will overwrite anything
     * you have done. Generally if you need to reset the timestamps, you should call
     * {@link #setAccountingInformation(HttpServletRequest, JSONObject)} instead.
     *
     * @param claims
     * @return
     * @throws Throwable
     */
    public JSONObject initializeClaims(HttpServletRequest request, JSONObject claims) {

        dbg(this, "Starting to process basic claims");
        String issuer = null;
        // So in order
        // 1. get the issuer from the admin client
        List<Identifier> admins = oa2se.getPermissionStore().getAdmins(transaction.getClient().getIdentifier());

        for (Identifier adminID : admins) {
            AdminClient ac = oa2se.getAdminClientStore().get(adminID);
            if (ac != null) {
                if (ac.getIssuer() != null) {
                    issuer = ac.getIssuer();
                    break;
                }
            }
        }
        // 2. If the admin client does not have an issuer set, see if the client has one
        if (issuer == null) {
            issuer = ((OA2Client) transaction.getClient()).getIssuer();
        }

        // 3. If the client does not have one, see if there is a server default to use
        // The discovery servlet will try to use the server default or construct the issuer
        if (issuer == null) {
            issuer = OA2DiscoveryServlet.getIssuer(request);
        }
        claims.put(OA2Claims.ISSUER, issuer);
        claims.put(OA2Claims.SUBJECT, transaction.getUsername());
        claims.put(AUDIENCE, transaction.getClient().getIdentifierString());
        // now set all the timestamps and such.
        return setAccountingInformation(request, claims);
    }

    /**
     * Use this to check for any requires scopes that the request must have. It is usually best to check these in the
     * transaction since they have been normalized there, but the request is supplied too for completeness.
     *
     * @param t
     * @throws Throwable
     */
    protected void checkRequiredScopes(OA2ServiceTransaction t) throws Throwable {
        if(oa2se.isOIDCEnabled()){
            if(t.getOA2Client().isPublicClient() && !t.getScopes().contains(OA2Scopes.SCOPE_OPENID)){
                throw new OA2GeneralError(OA2Errors.INVALID_SCOPE, "invalid scope: no open id scope", HttpStatus.SC_UNAUTHORIZED,null);
            }
            if(t.getOA2Client().getScopes().contains(OA2Scopes.SCOPE_OPENID) && !t.getScopes().contains(OA2Scopes.SCOPE_OPENID)){
                throw new OA2GeneralError(OA2Errors.INVALID_SCOPE, "invalid scope: no open id scope", HttpStatus.SC_UNAUTHORIZED,null);
            }
        }else{
             // no scopes are possible in certain OAuth 2 cases.
        }
/*
        if (oa2se.isOIDCEnabled() &&  !t.getScopes().contains(OA2Scopes.SCOPE_OPENID)) {
            throw new OA2GeneralError(OA2Errors.INVALID_SCOPE, "invalid scope: no open id scope", HttpStatus.SC_UNAUTHORIZED,null);
        }
*/
    }

    /**
     * creates new {@link ScriptRunRequest} with the basic information. This sends along the current claims, scopes
     * flow states and claim sources then harvests them <i>in toto</i> from the response.
     *
     * @return
     */
    protected ScriptRunRequest newSRR(OA2ServiceTransaction transaction, String phase) {
        ScriptRunRequest initReq = new ScriptRunRequest() {
            @Override
            public Map<String, Object> getArgs() {
                HashMap<String, Object> map = new HashMap<>();
                map.put(SRE_REQ_CLAIMS, transaction.getUserMetaData());
                JSONObject proxyState = transaction.getProxyState();
                if(proxyState.isEmpty()){
                    map.put(SRE_REQ_PROXY_CLAIMS, new JSONObject()); // it is empty
                }else{
                    proxyState.getJSONObject("claims");
                    map.put(SRE_REQ_PROXY_CLAIMS, proxyState.getJSONObject("claims"));
                }
                map.put(SRE_REQ_SCOPES, transaction.getScopes());
                map.put(SRE_REQ_AUDIENCE, transaction.getAudience());
                map.put(SRE_REQ_EXTENDED_ATTRIBUTES, transaction.getExtendedAttributes());
                map.put(SRE_REQ_FLOW_STATES, transaction.getFlowStates()); // so its a map
                try {
                    map.put(SRE_REQ_CLAIM_SOURCES, transaction.getClaimSources(oa2se)); // so its a map
                } catch (IOException | ClassNotFoundException e) {
                    throw new GeneralException("Error: Could not get the claim sources from the transaction", e);
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
     * @return
     */

    protected void handleSREResponse(ScriptRunResponse scriptRunResponse) throws IOException {
        switch (scriptRunResponse.getReturnCode()) {
            case ScriptRunResponse.RC_OK:
                // Note that the returned values from a script are very unlikely to be the same object we sent
                // even if the contents are the same, since scripts may have to change these in to other data structures
                // to make them accessible to their machinery, then convert them back.
                transaction.setUserMetaData((JSONObject) scriptRunResponse.getReturnedValues().get(SRE_REQ_CLAIMS));
                transaction.setFlowStates((FlowStates2) scriptRunResponse.getReturnedValues().get(SRE_REQ_FLOW_STATES));
                transaction.setClaimsSources((List<ClaimSource>) scriptRunResponse.getReturnedValues().get(SRE_REQ_CLAIM_SOURCES));

            case ScriptRunResponse.RC_NOT_RUN:
                return;

        }

        throw new NotImplementedException("Error: other script runtime reponses not implemented yet.");
    }


    /**
     * Creates the most basic claim object for this. These are claims that are common (e.g., set the openid
     * claim if this supports OIDC). This is the minimal set of claims for this service and is, e.g.
     * all that is returned to public clients. This also run the sources that are to run at initialization.
     * The assumption is that the initial sources can only be run exactly once during the first leg of the
     * OAuth transaction. These contain mutable information about the user from, say, Shibboleth headers or other
     * sources that will not be available later.
     *
     * @param request
     * @return
     * @throws Throwable
     */
    public JSONObject processAuthorizationClaims(HttpServletRequest request) throws Throwable {
        JSONObject claims = transaction.getUserMetaData();
        if (claims == null) {
            claims = new JSONObject();
        }
        claims = initializeClaims(request, claims);

        // claims are initialized and basic oidc scope (the subject) is included,
        transaction.setUserMetaData(claims);
        OA2Client client = getOA2Client();
        checkRequiredScopes(transaction);

        dbg(this, "Done with basic claims = " + claims.toString(1));
        if (transaction.getOA2Client().isPublicClient()) {
            // Public clients do not get more than basic claims.
            oa2se.getTransactionStore().save(transaction);
            return claims;
        }

        dbg(this, "Starting to process server default claims");

        if (oa2se != null && oa2se.getClaimSource() != null && oa2se.getClaimSource().isEnabled() && oa2se.getClaimSource().isRunAtAuthorization()) {
            DebugUtil.trace(this, "Service environment has a claims source enabled=" + oa2se.getClaimSource());

            // allow the server to pre-populate the claims. This invokes the global claims handler for the server
            // to allow, e.g. pulling user information out of HTTp headers.
            oa2se.getClaimSource().process(claims, request, transaction);
        } else {
            dbg(this, "Service environment has a claims no source enabled during authorization");
        }

        dbg(this, "Starting to process Client runtime and sources at authorization.");


        if (client.getConfig() == null || client.getConfig().isEmpty()) {
            // no configuration for this client means do nothing here.
            return claims;
        }
        // so this client has a specific configuration that is to be invoked.

        dbg(this, "executing runtime");
        FlowStates2 flowStates = new FlowStates2();
        transaction.setFlowStates(flowStates);
        List<ClaimSource> claimsSources = new ArrayList<>();

        ScriptRunRequest scriptRunRequest = null;
        if (getScriptRuntimeEngine() != null) {
            // Execute the init phase, if there is one in the config.
            scriptRunRequest = newSRR(transaction, SRE_EXEC_INIT);
            handleSREResponse(getScriptRuntimeEngine().run(scriptRunRequest));
            flowStates = transaction.getFlowStates();
            claimsSources = transaction.getClaimSources(oa2se);
            claims = transaction.getUserMetaData();
        }

        // This is out of band and might just be setting up state for later.
        dbg(this, "processing flows");
        if (flowStates.getClaims) {
            dbg(this, "Doing preprocessing");
            dbg(this, "Claims allowed, creating sources from configuration");
            // Execute scripts for pre-authorization phase.
            if (getScriptRuntimeEngine() != null) {
                scriptRunRequest = newSRR(transaction, SRE_PRE_AUTH);
                handleSREResponse(getScriptRuntimeEngine().run(scriptRunRequest));
                flowStates = transaction.getFlowStates();
                claimsSources = transaction.getClaimSources(oa2se);
                claims = transaction.getUserMetaData();
            }
            if (!claimsSources.isEmpty()) {
                // so there is
                for (int i = 0; i < claimsSources.size(); i++) {
                    ClaimSource claimSource = claimsSources.get(i);
                    if (claimSource.isRunAtAuthorization())
                        claimSource.process(claims, request, transaction);

                    // keep this in case this was set earlier.
                    if (!flowStates.acceptRequests) {
                        // This practically means that the come situation has arisen whereby the user is
                        // immediately banned from access -- e.g. they were found to be on a blacklist.
                        transaction.setUserMetaData(claims);
                        transaction.setFlowStates(flowStates);
                        oa2se.getTransactionStore().save(transaction);
                        throw new OA2GeneralError(OA2Errors.ACCESS_DENIED, "access denied", HttpStatus.SC_UNAUTHORIZED,null);
                    }
                    dbg(this, "user info for claim source #" + claimSource + " = " + claims.toString(1));
                }
            }

        }
        transaction.setUserMetaData(claims);
        transaction.setFlowStates(flowStates);
        // Execute scripts for post authorization phase..
        if (getScriptRuntimeEngine() != null) {
            scriptRunRequest = newSRR(transaction, SRE_POST_AUTH);
            // updating claim sources at this point is not done.
            handleSREResponse(getScriptRuntimeEngine().run(scriptRunRequest));
            // Note that this may still do things like reset the flow states or decide to remove a claim source
            // based on some criteria before the next round. Save it all.
            transaction.setScriptState(getScriptRuntimeEngine().serializeState());
        }
        // save it at this point because the flow states might, e.g. prohibit access to the entire system
        // and that has to be preserved against future access attempts.
        oa2se.getTransactionStore().save(transaction);
        return transaction.getUserMetaData();
    }

    protected OA2Client getOA2Client() {
        return transaction.getOA2Client();
    }


    /**
     * Gets the claims that are not done at authorization time. Typically these are done right before the
     * access token is created because there can be out of band calls that happen after the initial set of claims
     * is gotten and before this one is called, e.g., if this is part of a larger system and a bunch of
     * user information (not tracked by OA4MP) is updated before the grant is returned to the user.
     * CILogon is an example of this.
     *
     * @return
     * @throws Throwable
     */
    public JSONObject processClaims() throws Throwable {

        JSONObject claims = transaction.getUserMetaData();
        if (claims == null) {
            claims = new JSONObject();
        }
        if (transaction.getOA2Client().isPublicClient()) {
            // Public clients do not get claims, just a basic set of things to pass validation.
            return claims;
        }

        FlowStates2 flowStates = transaction.getFlowStates();
        // save everything up to this point since there are no guarantees that processing will continue:
        if (!flowStates.acceptRequests) {
            throw new OA2GeneralError(OA2Errors.ACCESS_DENIED, "access denied", HttpStatus.SC_UNAUTHORIZED,null);
        }
        OA2Client client = getOA2Client();

        if (client.getConfig() == null || client.getConfig().isEmpty()) {
            // no configuration for this client means do nothing here.
            return claims;
        }
        List<ClaimSource> claimsSources = transaction.getClaimSources(oa2se);
        ScriptRunRequest scriptRunRequest = null;
        if (getScriptRuntimeEngine() != null) {
            getScriptRuntimeEngine().deserializeState(transaction.getScriptState()); // put the state back the way it was

            scriptRunRequest = newSRR(transaction, SRE_PRE_AT);
            handleSREResponse(getScriptRuntimeEngine().run(scriptRunRequest));
            flowStates = transaction.getFlowStates();
            claimsSources = transaction.getClaimSources(oa2se);
            claims = transaction.getUserMetaData();
        }
        dbg(this, "BEFORE invoking claim sources, claims are = " + claims.toString(1));
        if (flowStates.getClaims) {
            DebugUtil.trace(this, "Claims allowed, creating sources from configuration");
            if (!claimsSources.isEmpty()) {
                // so there is
                for (int i = 0; i < claimsSources.size(); i++) {
                    ClaimSource claimSource = claimsSources.get(i);
                    if (!claimSource.isRunAtAuthorization()) {
                        if (claimSource instanceof BasicClaimsSourceImpl) {
                            // since the claim sources were just made, set the environment if it has not been set yet.
                            BasicClaimsSourceImpl b = (BasicClaimsSourceImpl) claimSource;
                            if (b.getOa2SE() == null) {
                                b.setOa2SE(oa2se);
                            }
                        }
                        DebugUtil.trace(this, "Before invoking claim source, new claims = " + claims.toString(1));
                        claimSource.process(claims, transaction);
                        DebugUtil.trace(this, "After invoking claim source, new claims = " + claims.toString(1));
                    }
                }
            }

        }
        // these might have changed in the course of executing the claim source.
        dbg(this, "Ready for post-processing");
        if (getScriptRuntimeEngine() != null) {
            scriptRunRequest = newSRR(transaction, SRE_POST_AT);
            handleSREResponse(getScriptRuntimeEngine().run(scriptRunRequest));
            claims = transaction.getUserMetaData();
            flowStates = transaction.getFlowStates();
        }
        // update everything
        checkRequiredClaims(claims);
        oa2se.getTransactionStore().save(transaction);
        dbg(this, "Done with special claims=" + claims.toString(1));
        // After post-processing it is possible that this user should be forbidden access, e.g. they are not in the correct group.
        // This is the first place we can check. If they are not allowed to make further requests, an access denied exception is thrown.
        if (!flowStates.acceptRequests) {
            dbg(this, "Access denied for user name = " + transaction.getUsername());
            throw new OA2GeneralError(OA2Errors.ACCESS_DENIED, "access denied", HttpStatus.SC_UNAUTHORIZED,null);
        }
        return transaction.getUserMetaData();
    }

    protected void checkRequiredClaim(JSONObject claims, String claimKey) {
        if (claims.containsKey(claimKey)) {
            if (isEmpty(claims.getString(claimKey))) {
                //           DebugUtil.trace(this, "Missing \"" + claimKey+ "\" claim= " );
                throw new OA2GeneralError(OA2Errors.SERVER_ERROR, "Missing " + claimKey + " claim", HttpStatus.SC_INTERNAL_SERVER_ERROR,null);
            }
        } else {
            throw new OA2GeneralError(OA2Errors.SERVER_ERROR, "Missing " + claimKey + " claim", HttpStatus.SC_INTERNAL_SERVER_ERROR,null);
        }

    }

    /**
     * For CIL-499. It is possible to remove key claims with functors and return unusable claims objects. This method
     * will check that claims that <b>must</b> be present are there or will raise a server-side exception.
     * CIL-540 Do not return empty claims either.
     *
     * @param claims
     */
    protected void checkRequiredClaims(JSONObject claims) {
        // only required one by the spec.
        if (oa2se.isOIDCEnabled()) {
            checkRequiredClaim(claims, SUBJECT);
        }
        // Remove empty claims. One should not assert empty claims.
        for (Object key : claims.keySet()) {

            if (key == null) {
                DebugUtil.error(this,"Null claim key encountered.");
                claims.remove(null);
            }
            String k = key.toString();
            if (k.isEmpty()) {
                DebugUtil.error(this,"Empty claim key encountered.");
                claims.remove(key);
            }
            if (claims.get(key) == null || claims.getString(k).isEmpty()) {
                DebugUtil.trace(this,"Removed empty claim \"" + key + "\"");
                claims.remove(key);
            }
        }

    }

    protected boolean isEmpty(String x) {
        return x == null || 0 == x.length();
    }

    protected void dbg(Object c, String x) {
        if (deepDebugOn) {
            DebugUtil.trace(c, x);
        }
    }
}
