package edu.uiuc.ncsa.myproxy.oa4mp.oauth2;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.FlowStates;
import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPServiceTransaction;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/28/14 at  1:46 PM
 */
public class OA2ServiceTransaction extends OA4MPServiceTransaction {
    public OA2ServiceTransaction(AuthorizationGrant ag) {
        super(ag);
    }

    public OA2ServiceTransaction(Identifier identifier) {
        super(identifier);
    }


     FlowStates flowStates;

    public FlowStates getFlowStates() {
        if(flowStates == null){
            flowStates = new FlowStates();
        }
        return flowStates;
    }

    public void setFlowStates(FlowStates flowStates) {
        this.flowStates = flowStates;
    }

    RefreshToken refreshToken;
    long refreshTokenLifetime = 0L;
    String nonce;

     public boolean hasAuthTime(){
         return authTime != null;
     }
    public Date getAuthTime() {
        return authTime;
    }

    public void setAuthTime(Date authTime) {
        this.authTime = authTime;
    }

    Date authTime = null;


    public Collection<String> getScopes() {
        if(scopes == null){
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
        x = x.substring(0,x.length()-1);
        x = x + ",refresh token="+getRefreshToken() + "]";
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
