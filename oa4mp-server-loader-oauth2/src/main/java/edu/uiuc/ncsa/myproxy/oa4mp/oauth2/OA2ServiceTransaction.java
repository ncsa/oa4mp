package edu.uiuc.ncsa.myproxy.oa4mp.oauth2;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.BasicClaimsSourceImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.FlowStates2;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPServiceTransaction;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;
import edu.uiuc.ncsa.security.delegation.token.impl.AuthorizationGrantImpl;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.FlowStates;
import edu.uiuc.ncsa.security.oauth_2_0.server.OA2TransactionScopes;
import edu.uiuc.ncsa.security.oauth_2_0.server.OIDCServiceTransactionInterface;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import net.sf.json.JSONObject;
import org.apache.commons.codec.binary.Base64;

import java.io.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.ExtendedParameters.EXTENDED_ATTRIBUTES_KEY;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/28/14 at  1:46 PM
 */
public class OA2ServiceTransaction extends OA4MPServiceTransaction implements OA2TransactionScopes, OIDCServiceTransactionInterface {
    public String FLOW_STATE_KEY = "flow_state";
    public String CLAIMS_SOURCES_STATE_KEY = "claims_sources";
    public String STATE_KEY = "state";
    public String STATE_COMMENT_KEY = "comment";
    public String CLAIMS_KEY = "claims";
    public String SCRIPT_STATE_KEY = "script_state";
    public String AUDIENCE_KEY = "audience";

    public OA2ServiceTransaction(AuthorizationGrant ag) {
        super(ag);
    }

    public OA2ServiceTransaction(Identifier identifier) {
        super(identifier);
        AuthorizationGrantImpl ag = null;
        if (identifier == null) {
            ag = new AuthorizationGrantImpl(null);
        } else {
            ag = new AuthorizationGrantImpl(identifier.getUri());
        }
        this.authorizationGrant = ag;
    }

    /**
     * Convenience cast.
     *
     * @return
     */
    public OA2Client getOA2Client() {
        return (OA2Client) getClient();
    }


    @Override
    public FlowStates2 getFlowStates() {
        JSONObject fs = getState().getJSONObject(FLOW_STATE_KEY);
        FlowStates2 flowStates = new FlowStates2();
        if (fs == null) {
            return flowStates;
        }
        if (!(fs == null || fs.isEmpty())) {
            flowStates.fromJSON(fs);
        }
        return flowStates;
    }

    public long getAccessTokenLifetime() {
        return access_token_lifetime;
    }

    public void setAccessTokenLifetime(long access_token_lifetime) {
        this.access_token_lifetime = access_token_lifetime;
    }

    long access_token_lifetime = 0L;

    /**
     * Clients may send an audience which is used by some components (notable SciTokens) but
     * is generally optional.
     *
     * @return
     */
    public List<String> getAudience() {
        if (getState().containsKey(AUDIENCE_KEY)) {
            return getState().getJSONArray(AUDIENCE_KEY);
        }
        return null;
    }

    public void setAudience(List<String> audience) {
        getState().put(AUDIENCE_KEY, audience);
    }

    public void setState(JSONObject state) {
        this.state = state;
    }

    // This is used to store the flow states, claim sources AND the claims in between calls.
    public JSONObject getState() {
        if (state == null) {
            state = new JSONObject();
            state.put(STATE_COMMENT_KEY, "State for object id \"" + getAuthorizationGrant().getToken() + "\"");
        }
        return state;
    }

    /**
     * Extended attributes are sent over the wire as specific requests.
     *
     * @return
     */
    public JSONObject getExtendedAttributes() {
        if (!getState().containsKey(EXTENDED_ATTRIBUTES_KEY)) {
            return new JSONObject();
        }

        return getState().getJSONObject(EXTENDED_ATTRIBUTES_KEY);
    }

    long grantLifetime = 15 * 60 * 1000L;

    @Override
    public long getAuthzGrantLifetime() {
        return grantLifetime;
    }

    public void setAuthGrantLifetime(long lifetime) {
        grantLifetime = lifetime;
    }

    public void setExtendedAttributes(JSONObject jsonObject) {
        // Again the format of the object from the extended parameters parsing is {"extendedAttributes":[]}
        // and we store the array with that key, not the entire object.
        if (jsonObject.containsKey(EXTENDED_ATTRIBUTES_KEY)) {
            // The thing is at the wrong level. Make sure we put it at the right one.
            getState().put(EXTENDED_ATTRIBUTES_KEY, jsonObject.getJSONObject(EXTENDED_ATTRIBUTES_KEY));
        } else {
            if (!jsonObject.isEmpty()) {
                getState().put(EXTENDED_ATTRIBUTES_KEY, jsonObject);
            }

        }
    }

    JSONObject state;

    @Override
    public void setFlowStates(FlowStates flowStates) {
        getState().put(FLOW_STATE_KEY, flowStates.toJSON());
    }

    public void setClaimsSources(List<ClaimSource> sources) throws IOException {
        /*
           At this point, serializing the sources to JSON is a daunting task in general, since
           turning them in to JSON, e.g., requires figuring out JSON serializations for
           things like the Java LDAP library, which is massive and I have no control over.
           Since the objects here
           exist for only the duration of the transaction, there should never be a deserialization issue.
           AND it has been said that roughly half of all Java security bugs relate to object serialization.
           This is probably true, except that this when object are serialized, sent over a network and
           intercepted -- nothing internal to the serialized object prevents tinkering.
           These object go straight to a database, never to see the light of day, so security
           is not an issue here. 
        */
        if (sources == null || sources.isEmpty()) {
            return;
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream(baos);
        out.writeObject(sources);
        out.flush();
        out.close();
        String s = Base64.encodeBase64URLSafeString(baos.toByteArray());
        getState().put(CLAIMS_SOURCES_STATE_KEY, s);
    }


    public List<ClaimSource> getClaimSources(OA2SE oa2SE) throws IOException, ClassNotFoundException {
        if (!getState().containsKey(CLAIMS_SOURCES_STATE_KEY)) {
            return new ArrayList<>();
        }
        String state = getState().getString(CLAIMS_SOURCES_STATE_KEY);
        byte[] bytes = Base64.decodeBase64(state);
        ByteArrayInputStream baos = new ByteArrayInputStream(bytes);
        ObjectInputStream in = new ObjectInputStream(baos);

        // Method for deserialization of object
        Object object = in.readObject();
        List<ClaimSource> sources = (List<ClaimSource>) object;
        for (ClaimSource source : sources) {
            if (source instanceof BasicClaimsSourceImpl) {
                ((BasicClaimsSourceImpl) source).setOa2SE(oa2SE);
            }
        }
        in.close();
        return sources;
    }

    /**
     * Script engines have the option to save their state between calls too. The argument is a (probably base 64 encoded)
     * string that will be returned on request.
     *
     * @param scriptState
     */
    public void setScriptState(String scriptState) {
        if (scriptState != null && !scriptState.isEmpty()) {
            getState().put(SCRIPT_STATE_KEY, scriptState);
        }
    }

    public boolean hasScriptState(){
        return getState().containsKey(SCRIPT_STATE_KEY);

    }
    public String getScriptState() {
        if (getState().containsKey(SCRIPT_STATE_KEY)) {
            return getState().getString(SCRIPT_STATE_KEY);
        }
        return "";
    }

    @Override
    public JSONObject getUserMetaData() {
        if (!getState().containsKey(CLAIMS_KEY)) {
            return new JSONObject();
        }
        return getState().getJSONObject(CLAIMS_KEY);
    }


    public void setUserMetaData(JSONObject claims) {
        getState().put(CLAIMS_KEY, claims);
    }

    String AT_DATA_KEY = "at_data"; // access token contents

    public JSONObject getATData() {
        if (!getState().containsKey(AT_DATA_KEY)) {
            return new JSONObject();
        }
        return getState().getJSONObject(AT_DATA_KEY);
    }

    public void setATData(JSONObject atData) {
        getState().put(AT_DATA_KEY, atData);
    }

    String RT_DATA_KEY = "rt_data"; // refresh token contents

    public void setRTData(JSONObject rtData) {
        getState().put(RT_DATA_KEY, rtData);
    }

    public JSONObject getRTData() {
        if (!getState().containsKey(RT_DATA_KEY)) {
            return new JSONObject();
        }
        return getState().getJSONObject(RT_DATA_KEY);
    }

    String RESPONSE_MODE_KEY = OA2Constants.RESPONSE_MODE;

    public String getResponseMode() {
        return getState().getString(RESPONSE_MODE_KEY);
    }

    public void setResponseMode(String mode) {
        getState().put(RESPONSE_MODE_KEY, mode);
    }

    public boolean hasResponseMode() {
        return getState().containsKey(RESPONSE_MODE_KEY);
    }

    String MAX_AT_LIFETIME_KEY = "maxATLifetime";
    String REQUESTED_AT_LIFETIME_KEY = "requestedATLifetime";
    String MAX_RT_LIFETIME_KEY = "maxRTLifetime";
    String REQUESTED_RT_LIFETIME_KEY = "requestedRTLifetime";

    public long getRequestedATLifetime(){
        if(hasRequestedATLifetime()){
            return getState().getLong(REQUESTED_AT_LIFETIME_KEY);
        }
        return -1L;
    }
    public boolean hasRequestedATLifetime(){
        return getState().containsKey(REQUESTED_AT_LIFETIME_KEY);
    }
    public void setRequestedATLifetime(long atLifetime){
        getState().put(REQUESTED_AT_LIFETIME_KEY, atLifetime);
    }
    public long getRequestedRTLifetime(){
        if(hasRequestedRTLifetime()){
            return getState().getLong(REQUESTED_RT_LIFETIME_KEY);
        }
        return -1L;
    }
    public void setRequestedRTLifetime(long rtLifetime){
        getState().put(REQUESTED_RT_LIFETIME_KEY, rtLifetime);
    }
    public boolean hasRequestedRTLifetime(){
        return getState().containsKey(REQUESTED_RT_LIFETIME_KEY);
    }
    public long getMaxAtLifetime(){
        if(hasMaxATLifetime()){
             return getState().getLong(MAX_AT_LIFETIME_KEY);
        }
        return -1L;
    }
    public void setMaxATLifetime(long max){
        getState().put(MAX_AT_LIFETIME_KEY, max);
    }

    public boolean hasMaxATLifetime(){
        return getState().containsKey(MAX_AT_LIFETIME_KEY);
    }

    public long getMaxRtLifetime(){
        if(hasMaxATLifetime()){
             return getState().getLong(MAX_RT_LIFETIME_KEY);
        }
        return -1L;
    }
    public void setMaxRTLifetime(long max){
        getState().put(MAX_RT_LIFETIME_KEY, max);
    }

    public boolean hasMaxRTLifetime(){
        return getState().containsKey(MAX_RT_LIFETIME_KEY);
    }


    RefreshToken refreshToken;
    long refreshTokenLifetime = 0L;
    String nonce;

    public boolean hasAuthTime() {
        return authTime != null;
    }

    public Date getAuthTime() {
        return authTime;
    }

    public void setAuthTime(Date authTime) {
        this.authTime = authTime;
    }

    Date authTime = new Date();

    /**
     * The <b><i>resolved</i></b> scopes for this transaction. This means that the intersection of the client's allowed
     * scopes, the client's requested scopes and the scopes enabled on the server are placed here. This should be passed
     * to anything that needs the scopes (e.g. a {@link edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource}.
     *
     * @return
     */
    @Override
    public Collection<String> getScopes() {
        if (scopes == null) {
            scopes = new ArrayList<>();
        }
        return scopes;
    }

    @Override
    public void setScopes(Collection<String> scopes) {
        this.scopes = scopes;
    }

    Collection<String> scopes = null;

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public boolean isRefreshTokenValid() {
        return refreshTokenValid;
    }

    public void setRefreshTokenValid(boolean refreshTokenValid) {
        this.refreshTokenValid = refreshTokenValid;
    }

    boolean refreshTokenValid = false;

    public long getRefreshTokenLifetime() {
        return refreshTokenLifetime;
    }

    public void setRefreshTokenLifetime(long refreshTokenLifetime) {
        this.refreshTokenLifetime = refreshTokenLifetime;
    }

    public boolean hasRefreshToken() {
        return refreshToken != null;
    }

    public RefreshToken getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(RefreshToken refreshToken) {
        this.refreshToken = refreshToken;
    }

    @Override
    protected String formatToString() {
        return super.formatToString() + ", nonce=" + getNonce() + ", scopes=" + getScopes() + ", refresh token lifetime=" + getRefreshTokenLifetime();
    }

    @Override
    public String toString() {
        String x = super.toString();
        x = x.substring(0, x.length() - 1);
        x = x + ",refresh token=" + getRefreshToken() + "]";
        return x;
    }

    @Override
    public boolean equals(Object obj) {
        boolean rc = super.equals(obj);
        if (!rc) return false;
        OA2ServiceTransaction st2 = (OA2ServiceTransaction) obj;
        if (getRefreshTokenLifetime() != st2.getRefreshTokenLifetime()) return false;
        if (getRefreshToken() == null) {
            if (st2.getRefreshToken() != null) return false;
        } else {
            if (!getRefreshToken().equals(st2.getRefreshToken())) return false;
        }
        if (isRefreshTokenValid() != st2.isRefreshTokenValid()) return false;
        return true;
    }
}
