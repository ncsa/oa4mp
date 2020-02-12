package edu.uiuc.ncsa.myproxy.oa4mp.oauth2;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.BasicClaimsSourceImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.FlowStates;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPServiceTransaction;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;
import edu.uiuc.ncsa.security.oauth_2_0.server.OA2TransactionScopes;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import net.sf.json.JSONObject;
import org.apache.commons.codec.binary.Base64;

import java.io.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/28/14 at  1:46 PM
 */
public class OA2ServiceTransaction extends OA4MPServiceTransaction implements OA2TransactionScopes {
    public String FLOW_STATE_KEY = "flow_state";
    public String CLAIMS_SOURCES_STATE_KEY = "claims_sources";
    public String STATE_KEY = "state";
    public String STATE_COMMENT_KEY = "comment";
    public String CLAIMS_KEY = "claims";
    public String SCRIPT_STATE_KEY = "script_state";

    public OA2ServiceTransaction(AuthorizationGrant ag) {
        super(ag);
    }

    public OA2ServiceTransaction(Identifier identifier) {
        super(identifier);
    }

    /**
     * Convenience cast.
     *
     * @return
     */
    public OA2Client getOA2Client() {
        return (OA2Client) getClient();
    }


    public FlowStates getFlowStates() {
        JSONObject fs = getState().getJSONObject(FLOW_STATE_KEY);
        FlowStates flowStates = new FlowStates();
        if (fs == null) {
            return flowStates;
        }
        if (!(fs == null || fs.isEmpty())) {
            flowStates.fromJSON(fs);
        }
        return flowStates;
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

    JSONObject state;

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
        if(sources== null || sources.isEmpty()){
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
        if(!getState().containsKey(CLAIMS_SOURCES_STATE_KEY)){
            return new ArrayList<>();
        }
        String state = getState().getString(CLAIMS_SOURCES_STATE_KEY);
        byte[] bytes = Base64.decodeBase64(state);
        ByteArrayInputStream baos = new ByteArrayInputStream(bytes);
        ObjectInputStream in = new ObjectInputStream(baos);

        // Method for deserialization of object
        Object object =  in.readObject();
        List<ClaimSource> sources = (List<ClaimSource>) object;
        for(ClaimSource source: sources){
            if(source instanceof BasicClaimsSourceImpl){
                ((BasicClaimsSourceImpl)source).setOa2SE(oa2SE);
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

    public String getScriptState() {
        if (getState().containsKey(SCRIPT_STATE_KEY)) {
            return getState().getString(SCRIPT_STATE_KEY);
        }
        return "";
    }

    @Override
    public JSONObject getClaims() {
        if (!getState().containsKey(CLAIMS_KEY)) {
            return new JSONObject();
        }
        return getState().getJSONObject(CLAIMS_KEY);
    }

    public void setClaims(JSONObject claims) {
        getState().put(CLAIMS_KEY, claims);
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

    Date authTime = null;

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
