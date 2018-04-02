package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;
import edu.uiuc.ncsa.security.oauth_2_0.UserInfo;
import edu.uiuc.ncsa.security.oauth_2_0.server.ClaimSource;
import edu.uiuc.ncsa.security.oauth_2_0.server.OA2Claims;
import edu.uiuc.ncsa.security.oauth_2_0.server.UnsupportedScopeException;
import net.sf.json.JSONObject;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 8/17/15 at  4:10 PM
 */
public class BasicClaimsSourceImpl implements ClaimSource {
    public BasicClaimsSourceImpl(OA2SE oa2SE) {
        this.oa2SE = oa2SE;
    }

    public BasicClaimsSourceImpl() {
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    boolean enabled = true;
    public boolean isEnabled(){
        return enabled;
    }
    /**
     * Optionally, the service environment may be injected into a scope handler to get configuration of
     * components, e.g.
     * @return
     */
    public OA2SE getOa2SE() {
        return oa2SE;
    }

    public void setOa2SE(OA2SE oa2SE) {
        this.oa2SE = oa2SE;
    }

    OA2SE oa2SE;
    Collection<String> scopes;

    @Override
    public Collection<String> getScopes() {
        return scopes;
    }

    /**
     * At the most basic level, this just returns the {@link UserInfo} object passed to it. Override as you deem fit.
     *
     * @param userInfo
     * @param transaction
     * @return
     * @throws UnsupportedScopeException
     */
    @Override
    public UserInfo process(UserInfo userInfo, ServiceTransaction transaction) throws UnsupportedScopeException {
        return process(userInfo, null, transaction);
    }

    /**
     * This also just returns the {@link UserInfo} object passed in.
     * @param userInfo
     * @param request
     * @param transaction
     * @return
     * @throws UnsupportedScopeException
     */
    @Override
    public UserInfo process(UserInfo userInfo, HttpServletRequest request, ServiceTransaction transaction) throws UnsupportedScopeException {
        if(claimsProcessor != null) {
            Map<String,Object> claims =userInfo.getMap();
            claims = getClaimsHandler(((OA2Client)transaction.getClient()).getClaimsConfig()).process(claims);
            userInfo.setMap(claims);
        }
        return userInfo;
    }

    public ClaimsProcessor getClaimsHandler(JSONObject config) {
        if(claimsProcessor == null){
            claimsProcessor = new ClaimsProcessor(config);
        }
        return claimsProcessor;
    }


    ClaimsProcessor claimsProcessor;
    @Override
    public void setScopes(Collection<String> scopes) {
        this.scopes = scopes;
    }

    /**
     * returns a (unique) collection of claims.
     * @return
     */
    @Override
    public Collection<String> getClaims() {
        HashSet<String> claims = new HashSet<>();
        claims.add(OA2Claims.ISSUER);
        claims.add(OA2Claims.SUBJECT);
        claims.add(OA2Claims.AUDIENCE);
        claims.add(OA2Claims.ISSUED_AT);
        claims.add(OA2Claims.EMAIL);
        claims.add(OA2Claims.EXPIRATION);

        return claims;
    }
}
