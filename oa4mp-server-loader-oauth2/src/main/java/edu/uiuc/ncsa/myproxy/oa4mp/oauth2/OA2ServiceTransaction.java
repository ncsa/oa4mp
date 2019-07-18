package edu.uiuc.ncsa.myproxy.oa4mp.oauth2;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.FlowStates;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPServiceTransaction;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;
import edu.uiuc.ncsa.security.oauth_2_0.server.OA2TransactionScopes;
import net.sf.json.JSONObject;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/28/14 at  1:46 PM
 */
public class OA2ServiceTransaction extends OA4MPServiceTransaction implements OA2TransactionScopes {
    public String FLOW_STATE_KEY = "flow_state";
    public String STATE_KEY = "state";
    public String STATE_COMMENT_KEY = "comment";
    public String CLAIMS_KEY = "claims";

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


    @Override
    public JSONObject getClaims() {
        if(!getState().containsKey(CLAIMS_KEY)){
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
