package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.FlowStates2;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.functor.FunctorRuntimeEngine;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.functor.claims.OA2FunctorFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.GroupHandler;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.oauth_2_0.UserInfo;
import edu.uiuc.ncsa.security.oauth_2_0.server.UnsupportedScopeException;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSourceConfiguration;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.JSONClaimSourceConfig;
import edu.uiuc.ncsa.security.util.functor.parser.FunctorScript;
import net.sf.json.JSONObject;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 8/17/15 at  4:10 PM
 */
public class BasicClaimsSourceImpl implements ClaimSource {

    /**
     * This is the list of claims from the headers to omit. In other words, this module will reject these out of hand
     * and never return them in a claims object. This is extremely useful in not having existing claims being over-written
     * (which can happen if something like mod_auth_openidc is acting as an intermediary and adding spurious claims.)
     *
     * @return
     */
    public List<String> getOmitList() {
        if (hasConfiguration()) {
            return getConfiguration().getOmitList();
        } else {
            return new LinkedList<>();
        }
    }

    public void setOmitList(List<String> omitList) {
        getConfiguration().setOmitList(omitList);
    }


    ClaimSourceConfiguration configuration = null;

    @Override
    public void setConfiguration(ClaimSourceConfiguration configuration) {
        this.configuration = configuration;
    }

    @Override
    public ClaimSourceConfiguration getConfiguration() {
        return configuration;
    }

    @Override
    public boolean hasConfiguration() {
        return configuration != null;
    }

    public boolean hasJSONPreProcessor() {
        if (getConfiguration() instanceof JSONClaimSourceConfig) {
            return ((JSONClaimSourceConfig) getConfiguration()).getJSONPreProcessing() != null;

        }
        return false;
    }

    public boolean hasJSONPostProcessor() {
        if (getConfiguration() instanceof JSONClaimSourceConfig) {
            return ((JSONClaimSourceConfig) getConfiguration()).getJSONPostProcessing() != null;

        }
        return false;
    }

    public BasicClaimsSourceImpl(OA2SE oa2SE) {
        this.oa2SE = oa2SE;
    }

    public BasicClaimsSourceImpl() {
    }


    public boolean isEnabled() {
        return getConfiguration().isEnabled();
    }

    /**
     * Optionally, the service environment may be injected into a scope handler to get configuration of
     * components, e.g.
     *
     * @return
     */
    public OA2SE getOa2SE() {
        return oa2SE;
    }

    public void setOa2SE(OA2SE oa2SE) {
        this.oa2SE = oa2SE;
    }

    transient OA2SE oa2SE; // do NOT serialize this. Ever.
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
     *
     * @param claims
     * @param request
     * @param transaction
     * @return
     * @throws UnsupportedScopeException
     */
    @Override
    public JSONObject process(JSONObject claims, HttpServletRequest request, ServiceTransaction transaction) throws UnsupportedScopeException {
        OA2ServiceTransaction t = (OA2ServiceTransaction) transaction;
        // NOTE This runs functor pre and post processors if they are in the source configuration.
        // The older version of scripting that used functors (which is quite primitive) did not
        // actually have a way to save its state nor good control of its execution flow, hence
        // pre and post processors were needed. If you remove these, you will probably break every older
        // configuration, so until nobody is using the old scripting, these must remain.
        DebugUtil.trace(this, "Before preP claims:" + claims);
        DebugUtil.trace(this, "Before preP has config:" + hasConfiguration());
        if (hasConfiguration() && hasJSONPreProcessor()) {
            DebugUtil.trace(this, "in preP cfg name=:" + getConfiguration().getName() + ", id=" + getConfiguration().getId());

            OA2FunctorFactory ff = new OA2FunctorFactory(claims, t.getScopes());
            preProcessor = new FunctorScript(ff, getConfiguration().getJSONPreProcessing());
            DebugUtil.trace(this, "PreP before X=:" + preProcessor);
            preProcessor.execute();
            DebugUtil.trace(this, "PreP after X=:" + preProcessor);

            // since the flow state maps to  part of a JSON object, we have to get the object, then reset it.
            FlowStates2 f = t.getFlowStates();
            FunctorRuntimeEngine.updateFSValues(f, preProcessor.getFunctorMap());
            t.setFlowStates(f);
        }
        DebugUtil.trace(this, "starting real processing");
        realProcessing(claims, request, t); // actual work here
        DebugUtil.trace(this, "done real processing, claims=" + claims);

        if (hasConfiguration() && hasJSONPostProcessor()) {
            DebugUtil.trace(this, "in postP cfg name=:" + getConfiguration().getName() + ", id=" + getConfiguration().getId());

            OA2FunctorFactory ff = new OA2FunctorFactory(claims, t.getScopes());
            postProcessor = new FunctorScript(ff, getConfiguration().getJSONPostProcessing());
            DebugUtil.trace(this, "postP before X=:" + postProcessor);

            postProcessor.execute();
            DebugUtil.trace(this, "postP after X=:" + postProcessor);
            FlowStates2 f = t.getFlowStates();
            FunctorRuntimeEngine.updateFSValues(f, postProcessor.getFunctorMap());
            t.setFlowStates(f);
        }
        DebugUtil.trace(this,"returned claims=:" + claims );

        return claims;
    }


    protected GroupHandler groupHandler = null;

    public GroupHandler getGroupHandler() {
        if (groupHandler == null) {
            groupHandler = new GroupHandler(); // default
        }
        return groupHandler;
    }

    public void setGroupHandler(GroupHandler groupHandler) {
        this.groupHandler = groupHandler;
    }

    /**
     * This is the actual place to put your code that only processes the claim source. The {@link #process(JSONObject, HttpServletRequest, ServiceTransaction)}
     * calls wrap this and invoke the pre/post processor for you. Your code should take whatever metadata is for the user
     * and add it to the claims object.
     *
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
     *
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

    FunctorScript preProcessor = null;
    FunctorScript postProcessor = null;

    @Override
    public FunctorScript getPostProcessor() {
        return postProcessor;
    }

    @Override
    public FunctorScript getPreProcessor() {
        return preProcessor;
    }

}
