package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.oauth_2_0.UserInfo;
import edu.uiuc.ncsa.security.oauth_2_0.server.UnsupportedScopeException;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.JSONClaimSourceConfig;
import edu.uiuc.ncsa.security.util.functor.LogicBlocks;
import net.sf.json.JSONObject;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.HashSet;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 8/17/15 at  4:10 PM
 */
public class BasicClaimsSourceImpl implements ClaimSource {

    JSONClaimSourceConfig configuration = null;
    @Override
    public void setConfiguration(JSONClaimSourceConfig configuration) {
                                   this.configuration = configuration;
    }

    @Override
    public JSONClaimSourceConfig getConfiguration() {
        return configuration;
    }

    @Override
    public boolean hasConfiguration() {
        return configuration != null;
    }

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
     * @param claims
     * @param transaction
     * @return
     * @throws UnsupportedScopeException
     */
    @Override
    public JSONObject process(JSONObject claims, ServiceTransaction transaction) throws UnsupportedScopeException {
        return process(claims, null, transaction);
    }

    /**
     * This also just returns the {@link UserInfo} object passed in.
     * @param claims
     * @param request
     * @param transaction
     * @return
     * @throws UnsupportedScopeException
     */
    @Override
    public JSONObject process(JSONObject claims, HttpServletRequest request, ServiceTransaction transaction) throws UnsupportedScopeException {
        if(hasConfiguration() && getConfiguration().getPreProcessing()!= null){
                 OA2FunctorFactory ff = new OA2FunctorFactory(claims);
                 preProcessor = ff.createLogicBlock(getConfiguration().getPreProcessing());
                 preProcessor.execute();

             }
        realProcessing(claims, request, transaction);
        if(hasConfiguration() && getConfiguration().getPostProcessing()!= null){
            OA2FunctorFactory ff = new OA2FunctorFactory(claims);
            postProcessor = ff.createLogicBlock(getConfiguration().getPostProcessing());
            postProcessor.execute();
        }
        return claims;
    }

    /**
     * This is the actual place to put your code that only processes the claim source. The {@link #process(JSONObject, HttpServletRequest, ServiceTransaction)}
     * calls wrap this and invoke the pre/post processor for you.
     * @param claims
     * @param request
     * @param transaction
     * @return
     * @throws UnsupportedScopeException
     */
    protected JSONObject realProcessing(JSONObject claims, HttpServletRequest request, ServiceTransaction transaction) throws UnsupportedScopeException {
        return claims;

    }


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


    @Override
    public boolean isRunAtAuthorization() {
        return false;
    }

    LogicBlocks preProcessor = null;
    LogicBlocks postProcessor = null;

    @Override
    public LogicBlocks getPostProcessor() {
        return postProcessor;
    }

    @Override
    public LogicBlocks getPreProcessor() {
        return preProcessor;
    }
}
