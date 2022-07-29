package edu.uiuc.ncsa.oa4mp.delegation.oa2.jwt;

import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunRequest;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse;
import net.sf.json.JSONObject;

import java.io.Serializable;
import java.util.List;

/**
 * This class is charged with creating and managing the payload of a single type of JWT. As
 * we get more types of these (OIDC, SciToken, etc.) each of these has completely
 * separate requirements for creating, management and such. All of that should be encapsulated
 * into a class.
 * <p>Created by Jeff Gaynor<br>
 * on 2/15/20 at  7:13 AM
 */
public interface PayloadHandler extends Serializable {
    /**
     * Creates and initializes the claims object this class manages.
     */
    void init() throws Throwable;

    /**
     * If the claims need to be updated (e.g. for a refresh and the timestamps need
     * adjusting) this method needs to be called. It's contract is to reget all of the
     * claims.
     */
    void refresh()  throws Throwable;

    /**
     * Marshall any resources this script needs to make a request.
     * I.e., add specific state (if needed) from this handler
     * to the {@link ScriptRunRequest}.
     * @return
     */
    void addRequestState(ScriptRunRequest req)  throws Throwable;

    /**
     * This takes the response from a script and unmarshalls the resources
     * @param resp
     */
    void handleResponse(ScriptRunResponse resp)  throws Throwable;

    /**
     * Called after the runner has gotten the claims so that this class can check integrity.
     * For instance, an OIDC server would need to see that the subject is set properly.
     * SciTokens needs to check that its scopes (aka resource permissions) were set
     */
    void checkClaims()  throws Throwable;

    /**
     * These are the sources that the runner will use to populate the claims
     * @return
     */
    List<ClaimSource> getSources()  throws Throwable;

    /**
     * Runs this specific claim source against the internal state of this class.
     * Note that the contract is that it returns the updated claims and if there
     * are no new claims, it should just return its claims argument.
     * @param claims
     * @return
     */
    JSONObject execute(ClaimSource source, JSONObject claims)  throws Throwable;
    /**
     * Called at the very end of all processing, this lets the handler, clean up or whatever it needs to do.
     * It is called before {@link #saveState()}.
     * @param execPhase - the current execution phase.
     */
    void finish(String execPhase)  throws Throwable;
    /**
     * Called at the end of each block, this lets the handler save its state. Note that for OA4MP,
     * the state is saved in the transaction which is saved once after the handlers run. Only
     * put actual save code in here if needed, since it is apt to get called a lot.
     */

    void saveState()  throws Throwable;
    /**
     * Get the claims (the actual payload).
     * @return
     */
    JSONObject getClaims()  throws Throwable;

    JSONObject getExtendedAttributes() throws Throwable;

    /**
     * This sets the accounting information (such as the expiration and such) for a token.
     * This is called when a token is created or refreshed. 
     */
    void setAccountingInformation();

    /**
     * This is used on refresh only. It will reset all the standard accounting information
     * (such as timestamps) for an existing claims object.
     * <h4>Usage</h4>
     * Create an instance of the handler with the constructor for any state, then invoke this method.
     */
    void refreshAccountingInformation();

    public PayloadHandlerConfig getPhCfg() ;

    public void setPhCfg(PayloadHandlerConfig phCfg);

    boolean hasScript();

    /**
     * Returns the payload from this handler encoded with a key, if applicable.
     * @param key
     * @return
     */
    public String getToken(JSONWebKey key);
    public void setResponseCode(int responseCode);
    public int getResponseCode();
}
