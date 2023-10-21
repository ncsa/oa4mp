package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.transactions;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.BasicClaimsSourceImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.FlowStates2;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.RFC8628State;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims.ConfigtoCS;
import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPServiceTransaction;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AuthorizationGrant;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.RefreshToken;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.AuthorizationGrantImpl;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Constants;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.jwt.FlowStates;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.OA2TransactionScopes;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.OIDCServiceTransactionInterface;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.RFC7636Util;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.ClaimSource;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.OA2Claims;
import edu.uiuc.ncsa.qdl.variables.QDLStem;
import edu.uiuc.ncsa.security.core.DateComparable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.codec.binary.Base64;

import java.io.*;
import java.net.URI;
import java.util.*;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.ExtendedParameters.EXTENDED_ATTRIBUTES_KEY;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/28/14 at  1:46 PM
 */
public class OA2ServiceTransaction extends OA4MPServiceTransaction implements OA2TransactionScopes, OIDCServiceTransactionInterface, DateComparable {
    /*
      These keys are used internally as keys for the state JSON object. All you need to do is grab the state as a unit.
     */
    public String FLOW_STATE_KEY = "flow_state";
    public String CLAIMS_SOURCES_STATE_KEY = "claims_sources";
    public String CLAIMS_SOURCES_STATE_KEY2 = "claims_sources2";
    public String STATE_KEY = "state";
    public String STATE_COMMENT_KEY = "comment";
    public String CLAIMS_KEY = "claims";
    public String SCRIPT_STATE_KEY = "script_state";
    public String AUDIENCE_KEY = "audience";
    public String RESOURCE_KEY = "resource";
    public String QUERIED_ACCESS_TOKEN_SCOPES_KEY = "queriedATScopes";
    public String RETURNED_ACCESS_TOKEN_JWT_KEY = "atJWT";
    public String RETURNED_REFRESH_TOKEN_JWT_KEY = "rtJWT";


    public String getProxyId() {
        return proxyId;
    }

    public void setProxyId(String proxyId) {
        this.proxyId = proxyId;
    }

    public String proxyId;

    @Override
    public Date getCreationTS() {
        return getAuthTime();
    }

    public String getUserCode() {
        return userCode;
    }

    public void setUserCode(String userCode) {
        this.userCode = userCode;
    }

    String userCode;

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

    public static String RFC862_STATE_KEY = "rfc8628_state";


    public RFC8628State getRFC8628State() {
        JSONObject j = getState().getJSONObject(RFC862_STATE_KEY);
        RFC8628State state = new RFC8628State();
        if (j != null) {
            state.fromJSON(j);
        }
        return state;
    }

    static String PROXY_STATE_KEY = "proxy_state";

    public void setProxyState(JSONObject proxyState) {
        getState().put(PROXY_STATE_KEY, proxyState);
    }

    public JSONObject getProxyState() {
        if (getState().containsKey(PROXY_STATE_KEY)) {
            return getState().getJSONObject(PROXY_STATE_KEY);
        }
        return new JSONObject();
    }

    public void setRFC8628State(RFC8628State rfc8628State) {
        getState().put(RFC862_STATE_KEY, rfc8628State.toJSON());
    }

    public long getAccessTokenLifetime() {
        return access_token_lifetime;
    }

    public void setAccessTokenLifetime(long access_token_lifetime) {
        this.access_token_lifetime = access_token_lifetime;
    }

    long access_token_lifetime = 0L;

    public long getIDTokenLifetime() {
        return idTokenLifetime;
    }

    public void setIDTokenLifetime(long idTokenLifetime) {
        this.idTokenLifetime = idTokenLifetime;
    }

    long idTokenLifetime = 0L;


    /**
     * Clients may send an audience which is used by some components (notable SciTokens) but
     * is generally optional. This is a list of them. This is returned as the
     * {@link OA2Claims#AUDIENCE } claim
     * in JWT access tokens.
     * <br/><br/>
     * <b>Note:</b> These are simply logical names that describe the audience, such as "ALL"
     * or "ligo_cluster." Compare with {@link #getResource()} which has a list of URIs for the
     * same purpose.
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

    /**
     * The actual time the refresh token in the transaction expires.
     * @return
     */
    public long getRefreshTokenExpiresAt() {
        // Fixes https://github.com/ncsa/oa4mp/issues/129
        return refreshTokenExpiresAt;
    }

    public void setRefreshTokenExpiresAt(long refreshTokenExpiresAt) {
        this.refreshTokenExpiresAt = refreshTokenExpiresAt;
    }

    long refreshTokenExpiresAt = 0L;
    boolean isRFC8628 = false;

    public boolean isRFC8628Request() {
        return isRFC8628;
    }

    public void setRFC8628Request(boolean b) {
        isRFC8628 = b;
    }

    /**
     * Resources are URIs that are used as part of the {@link OA2Claims#AUDIENCE}
     * claim in a (compound) access token.
     *
     * @return
     */
    public List<String> getResource() {
        // This is a list of string and not URIs because it is in the state object which gets serialized
        // JSON which does very odd things to URIs. Best we can do is check that the elements are URIs
        // when setting it rather than writing some handler if it gets changed.
        if (getState().containsKey(RESOURCE_KEY)) {
            return getState().getJSONArray(RESOURCE_KEY);
        }
        return null;
    }

    public boolean hasResource(){
        return getState().containsKey(RESOURCE_KEY) && getState().get(RESOURCE_KEY)!=null;
    }

    public void setResource(List<String> r) {
        getState().put(RESOURCE_KEY, r);
    }

    /**
     * Generally you should never set the state directly unless you know exactly how it is constructed.
     *
     * @param state
     */
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

    public void setClaimsSources(List<ClaimSource> sources)  {
        if (sources == null || sources.isEmpty()) {
            return;
        }
        // CIL-1550
        newCSSerialize(sources);
        // We don't use this nor need it going forward.
        // It is maintained starting in 5.2.8.3 for backwards compatibility and will be removed at some point.
        oldCSSerialize(sources);
   //     oldCSSerialize(sources);
    }

    protected void  newCSSerialize(List<ClaimSource> sources) {
       JSONArray array = new JSONArray();
        for (ClaimSource claimSource : sources) {
            //array.add(ConfigtoCS.convert(claimSource).toJSON());
            array.add(claimSource.toQDL().toJSON());
        }
        getState().put(CLAIMS_SOURCES_STATE_KEY2, array);
    }

    protected void oldCSSerialize(List<ClaimSource> sources)  {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream out = new ObjectOutputStream(baos);
            out.writeObject(sources);
            out.flush();
            out.close();
            getState().put(CLAIMS_SOURCES_STATE_KEY, Base64.encodeBase64URLSafeString(baos.toByteArray()));
        }catch(Throwable t){
            if(t instanceof RuntimeException){
                throw (RuntimeException)t;
            }
            throw new GeneralException("error serializing claims:" + t.getMessage(), t);
        }
    }


    public List<ClaimSource> getClaimSources(OA2SE oa2SE) {
       // CIL-1550 with a vengeance.
        if (getState().containsKey(CLAIMS_SOURCES_STATE_KEY2)) {
            try{
                 return newCSDeserialize(oa2SE);
            }catch(Throwable t){
                // try the old way.
                ServletDebugUtil.info(this, "could not deserialize claim sources new way, reverting to Java serialization");
            }
        }

        if (getState().containsKey(CLAIMS_SOURCES_STATE_KEY)) {
            try {
                return oldCSDeserialize(oa2SE);
            }catch(Throwable tt){
                // ok, some work to do. really blow up since there is no state stored.
                if(ServletDebugUtil.isEnabled()){
                    ServletDebugUtil.info(this, "could not deserialize claim sources in any way:" + tt.getMessage());
                    tt.printStackTrace();
                }
                if(tt instanceof RuntimeException){
                    throw (RuntimeException)tt;
                }
                throw new GeneralException("Error deserializing claim source:" + tt.getMessage(), tt);
            }
        }
        return new ArrayList<>();
    }
    protected ConfigtoCS configtoCS;
    public ConfigtoCS getConfigToCS(){
        if(configtoCS == null){
            configtoCS = new ConfigtoCS();
        }
        return configtoCS;
    }

    protected List<ClaimSource> newCSDeserialize(OA2SE oa2SE) throws Throwable {
          // Assumed to be a serialized JSON Array
        JSONArray array = getState().getJSONArray(CLAIMS_SOURCES_STATE_KEY2);
        ArrayList<ClaimSource> claimSources = new ArrayList<>();
        for(int i =0; i < array.size(); i++){
                 QDLStem stem = new QDLStem();
                 claimSources.add(getConfigToCS().convert(stem.fromJSON(array.getJSONObject(0)), oa2SE));
             }
        return claimSources;
    }

    protected List<ClaimSource> oldCSDeserialize(OA2SE oa2SE) throws Throwable {
        byte[] bytes = Base64.decodeBase64(getState().getString(CLAIMS_SOURCES_STATE_KEY));
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

    public boolean hasScriptState() {
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

    String PROVISIONING_ADMIN_ID = "provisioning_admin_id";

    public Identifier getProvisioningAdminID() {
        if (!getState().containsKey(PROVISIONING_ADMIN_ID)) {
            return null;
        }
        return BasicIdentifier.newID(getState().getString(PROVISIONING_ADMIN_ID));
    }

    /**
     * Sets the provisioning admin partly so we don't have to look it up again and partly so
     * that for very, very long lived transactions, there is absolutely no possibility
     * that the VO can change.
     *
     * @param provisioningAdminID
     */
    public void setProvisioningAdminID(Identifier provisioningAdminID) {
        getState().put(PROVISIONING_ADMIN_ID, provisioningAdminID==null?null:provisioningAdminID.toString());
    }

    String PROVISIONING_CLIENT_ID = "provisioning_client_id";

    /**
     * Set if this transaction is from a substitution. This is the ID of the client
     * that originally started the flow.
     *
     * @return
     */
    public Identifier getProvisioningClientID() {
        if (!getState().containsKey(PROVISIONING_CLIENT_ID)) {
            return null;
        }
        return BasicIdentifier.newID(getState().getString(PROVISIONING_CLIENT_ID));
    }

    public void setProvisioningClientID(Identifier provisioningClientID) {
        getState().put(PROVISIONING_CLIENT_ID, provisioningClientID.toString());
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
    String MAX_IDT_LIFETIME_KEY = "maxIDLifetime";
    String REQUESTED_AT_LIFETIME_KEY = "requestedATLifetime";
    String REQUESTED_IDT_LIFETIME_KEY = "requestedIDTLifetime";
    String MAX_RT_LIFETIME_KEY = "maxRTLifetime";
    String REQUESTED_RT_LIFETIME_KEY = "requestedRTLifetime";

    public long getRequestedATLifetime() {
        if (hasRequestedATLifetime()) {
            return getState().getLong(REQUESTED_AT_LIFETIME_KEY);
        }
        return -1L;
    }
    public long getRequestedIDTLifetime() {
        if (hasRequestedIDTLifetime()) {
            return getState().getLong(REQUESTED_IDT_LIFETIME_KEY);
        }
        return -1L;
    }

    public void setRequestedIDTLifetime(long idtLifetime) {
        getState().put(REQUESTED_IDT_LIFETIME_KEY, idtLifetime);
    }

    public boolean hasRequestedATLifetime() {
        return getState().containsKey(REQUESTED_AT_LIFETIME_KEY);
    }

    public boolean hasRequestedIDTLifetime() {
        return getState().containsKey(REQUESTED_IDT_LIFETIME_KEY);
    }

    public void setRequestedATLifetime(long atLifetime) {
        getState().put(REQUESTED_AT_LIFETIME_KEY, atLifetime);
    }

    public long getRequestedRTLifetime() {
        if (hasRequestedRTLifetime()) {
            return getState().getLong(REQUESTED_RT_LIFETIME_KEY);
        }
        return -1L;
    }

    public void setRequestedRTLifetime(long rtLifetime) {
        getState().put(REQUESTED_RT_LIFETIME_KEY, rtLifetime);
    }

    public boolean hasRequestedRTLifetime() {
        return getState().containsKey(REQUESTED_RT_LIFETIME_KEY);
    }

    public long getMaxAtLifetime() {
        if (hasMaxATLifetime()) {
            return getState().getLong(MAX_AT_LIFETIME_KEY);
        }
        return -1L;
    }

    public void setMaxATLifetime(long max) {
        Long ll = new Long(max);
        // weirdly enough, the JSON library converts it to an integer at times
        // which then fails later on the getMaxLifetime.
        getState().put(MAX_AT_LIFETIME_KEY, ll);
    }

    public long getMaxIDTLifetime() {
        if (hasMaxIDTLifetime()) {
            return getState().getLong(MAX_IDT_LIFETIME_KEY);
        }
        return -1L;
    }

    public void setMaxIDTLifetime(long max) {
        Long ll = new Long(max);
        // weirdly enough, the JSON library converts it to an integer at times
        // which then fails later on the getMaxLifetime.
        getState().put(MAX_IDT_LIFETIME_KEY, ll);
    }

    public boolean hasMaxATLifetime() {
        return getState().containsKey(MAX_AT_LIFETIME_KEY);
    }
    public boolean hasMaxIDTLifetime() {
        return getState().containsKey(MAX_IDT_LIFETIME_KEY);
    }

    public long getMaxRtLifetime() {
        if (hasMaxATLifetime()) {
            if (getState().containsKey(MAX_RT_LIFETIME_KEY)) {
                return getState().getLong(MAX_RT_LIFETIME_KEY);
            } else {
                throw new IllegalStateException(MAX_RT_LIFETIME_KEY + " not set for this transaction");
            }
        }
        return -1L;
    }

    public void setMaxRTLifetime(long max) {
        getState().put(MAX_RT_LIFETIME_KEY, max);
    }

    public boolean hasMaxRTLifetime() {
        return getState().containsKey(MAX_RT_LIFETIME_KEY);
    }

    /*
    The next 5 methods are for RFC 7636 support.
     */

    public boolean hasCodeChallenge() {
        return getState().containsKey(RFC7636Util.CODE_CHALLENGE);
    }

    public String getCodeChallenge() {
        return getState().getString(RFC7636Util.CODE_CHALLENGE);
    }

    public void setCodeChallenge(String codeChallenge) {
        getState().put(RFC7636Util.CODE_CHALLENGE, codeChallenge);
    }

    public String getCodeChallengeMethod() {
        return getState().getString(RFC7636Util.CODE_CHALLENGE_METHOD);
    }

    public void setCodeChallengeMethod(String codeChallengeMethod) {
        getState().put(RFC7636Util.CODE_CHALLENGE_METHOD, codeChallengeMethod);
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
     * to anything that needs the scopes (e.g. a {@link ClaimSource}.
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

    /**
     * The scopes <b><i>requested</i></b> by the client. This does not mean they are all
     * allowed, just so we have a list of them
     *
     * @param scopes
     */
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

    /**
     * This is, unfortunately, overloaded. It is the initial lifetime allowed by the
     * client and may be set in the registration. If &lt;=0 then refresh tokens are
     * disabled. The actual expiration for the refresh token in the transaction is
     * found in {@link #refreshTokenExpiresAt}.
     * @return
     */
    public long getRefreshTokenLifetime() {
        return refreshTokenLifetime;
    }

    public void setRefreshTokenLifetime(long refreshTokenLifetime) {
        this.refreshTokenLifetime = refreshTokenLifetime;
    }
    /**
     * This is the state parameter in the initial request, if present
     *
     * @return
     */
    public String getRequestState() {
        return requestState;
    }

    public void setRequestState(String requestState) {
        this.requestState = requestState;
    }

    String requestState = null;

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

    /**
     * The scopes that the user actually consented to on the user consent page. These are set
     * once and never updated to prevent up scoping.
     *
     * @return
     */
    public Collection<String> getValidatedScopes() {
        if (validatedScopes == null) {
            validatedScopes = new HashSet<>();
        }
        return validatedScopes;
    }

    public void setValidatedScopes(Collection<String> validatedScopes) {
        this.validatedScopes = validatedScopes;
    }

    Collection<String> validatedScopes;

    public Collection<String> getQueriedATScopes() {
        if (!getState().containsKey(QUERIED_ACCESS_TOKEN_SCOPES_KEY)) {
            return null;
        }
        return getState().getJSONArray(QUERIED_ACCESS_TOKEN_SCOPES_KEY);

    }

    public void setQueriedATScopes(Collection<String> queriedATScopes) {
        getState().put(QUERIED_ACCESS_TOKEN_SCOPES_KEY, queriedATScopes);
    }

    /**
     * If an JWT access token was returned, a copy is saved here.
     *
     * @return
     */
    public String getATJWT() {
        return atJWT;
    }

    String atJWT = null;

    public void setATJWT(String atJWT) {
        this.atJWT = atJWT;
    }

    /**
     * If an JWT refresh token was returned, a copy is saved here.
     *
     * @return
     */
    public String getRTJWT() {
        return rtJWT;
    }

    String rtJWT = null;

    public void setRTJWT(String rtJWT) {
        this.rtJWT = rtJWT;
    }

    /**
     * Get the last 6 characters of the unique part of an identifer
     *
     * @param id
     * @return
     */
    protected String firstSix(URI id) {
        String agID = id.getPath();
        if (agID == null) {
            // custom ids like foo:bar won't work with this, so return it all.
            return id.toString();
        }
        agID = agID.substring(agID.lastIndexOf("/") + 1);
        // CIL-1348 fix:
        if (6 < agID.length()) {
            int l = agID.length();
            // problem with first 6 is that some of these components end up being
            // timestamps so the first 6 is not even remotely unique.
            //return agID.substring(0, 6);
            return agID.substring(l - 6);
        }
        return id.toString();
    }

    String idTokenIdentifier = null;

    // https://github.com/ncsa/oa4mp/issues/128
    @Override
    public String getIDTokenIdentifier() {
        return idTokenIdentifier;
    }

    @Override
    public void setIDTokenIdentifier(String idTokenIdentifier) {
        this.idTokenIdentifier = idTokenIdentifier;
    }

    /**
     * Summary for debugging.
     *
     * @return
     */
    public String summary() {
        String out = "Transaction[id=" + firstSix(getIdentifier().getUri());
        if (hasAccessToken()) {
            out = out + ", at=" + firstSix(getAccessToken().getJti());
        }
        if (hasRefreshToken()) {
            out = out + ", rt=" + firstSix(getRefreshToken().getJti());
        }
        out = out + ", client=" + firstSix(getClient().getIdentifier().getUri());
        return out + "]";
    }
}
