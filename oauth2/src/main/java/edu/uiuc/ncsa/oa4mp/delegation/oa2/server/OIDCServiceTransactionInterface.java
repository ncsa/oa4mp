package edu.uiuc.ncsa.oa4mp.delegation.oa2.server;

import edu.uiuc.ncsa.oa4mp.delegation.oa2.jwt.FlowStates;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.ClaimSource;
import net.sf.json.JSONObject;

import java.util.Collection;
import java.util.List;

/**
 * Mostly this exists because of the inheritance hierarchy vis a vis the very ancient OAuth 1
 * code. In a refactoring, this would go away. Basically it exposes OAuth2 functionality.
 * <p>Created by Jeff Gaynor<br>
 * on 2/15/20 at  5:46 PM
 */
public interface OIDCServiceTransactionInterface {
    FlowStates getFlowStates();

    void setFlowStates(FlowStates flowStates);

    Collection<String> getScopes();
    void setClaimsSources(List<ClaimSource> sources);

    void setScopes(Collection<String> scopes);

    List<String> getAudience();

    void setAudience(List<String> audience);

    List<String> getResource();

    void setResource(List<String> resource);

    JSONObject getExtendedAttributes();

    void setExtendedAttributes(JSONObject xas);

    public JSONObject getUserMetaData();

    public void setUserMetaData(JSONObject claims);

    public long getAccessTokenLifetime();

    public long getRefreshTokenLifetime();

    public long getAuthzGrantLifetime();

    public String getProxyId();

    public void setProxyId(String proxyId);

    public JSONObject getProxyState();

    public void setProxyState(JSONObject proxyState);
    
    public String getIDTokenIdentifier();
    public void setIDTokenIdentifier(String idTokenIdentifier);

    public JSONObject getATData();
    public void setATData(JSONObject atData);

}

