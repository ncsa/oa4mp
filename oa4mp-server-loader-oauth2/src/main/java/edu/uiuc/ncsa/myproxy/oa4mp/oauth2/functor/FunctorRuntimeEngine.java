package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.functor;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.OA2FunctorFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.FlowStates;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.FlowType;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.OA2ClientFunctorScripts;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.OA2ClientFunctorScriptsFactory;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.util.functor.JFunctor;
import edu.uiuc.ncsa.security.util.functor.logic.FunctorMap;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunRequest;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse;
import edu.uiuc.ncsa.security.util.scripting.ScriptRuntimeEngine;
import net.sf.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.OA2ClaimsUtil.*;
import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.FlowType.*;
import static edu.uiuc.ncsa.security.core.util.DebugUtil.trace;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/6/20 at  2:04 PM
 */
public class FunctorRuntimeEngine extends ScriptRuntimeEngine {


    @Override
    public ScriptRunResponse run(ScriptRunRequest request) {
        switch (request.getAction()) {
            case SRE_EXEC_INIT:
                return doInit(request);
            case SRE_PRE_AUTH:
                return doPreAuth(request);
            case SRE_PRE_AT:
                return doPreAT(request);
            default:
                throw new NotImplementedException("Error: not implemented for action " + request.getAction());
        }
    }

    protected ScriptRunResponse createSRR(ScriptRunRequest scriptRunRequest) {
        return createSRR(scriptRunRequest, new ArrayList<>());
    }


    /**
     * After the request has been processed, call this to create the correct response object.
     *
     * @param scriptRunRequest
     * @param claimSources
     * @return
     */
    protected ScriptRunResponse createSRR(ScriptRunRequest scriptRunRequest, List<ClaimSource> claimSources) {
        Map respMap = new HashMap();
        if (scriptRunRequest.returnArgs()) {
            for (String key : scriptRunRequest.getArgs().keySet()) {
                respMap.put(key, scriptRunRequest.getArgs().get(key));
            }
        }
        if (scriptRunRequest.returnArgs()) {
            respMap.put(SRE_REQ_CLAIM_SOURCES, claimSources);
        }
        //runResponse.
        return new ScriptRunResponse("", respMap, ScriptRunResponse.RC_OK);
    }

    private ScriptRunResponse doPreAT(ScriptRunRequest request) {
        OA2FunctorFactory functorFactory = getFF((Map) request.getArgs().get(SRE_REQ_CLAIMS),
                (List) request.getArgs().get(SRE_REQ_SCOPES));
        OA2ClientFunctorScriptsFactory<OA2ClientFunctorScripts> ff = getScriptFactory(functorFactory);
        OA2ClientFunctorScripts cc = ff.newInstance();

        if (cc.hasPostProcessing()) {
            trace(this, ".doPostProcessing: has post-processing?" + cc.getPostProcessing());
            ff.setupPostProcessing(cc, config);
            cc.executePostProcessing();
            ff.createClaimSource(cc, config);
            FlowStates flowStates = (FlowStates) request.getArgs().get(SRE_REQ_FLOW_STATES);
            updateFSValues(flowStates, cc.getPostProcessing().getFunctorMap());

            trace(this, ".doPostProcessing: executed post-processing, functor map=" + cc.getPostProcessing().getFunctorMap());
            return createSRR(request, cc.getClaimSource());
        }
        return createSRR(request); // no claim sources
    }

    private ScriptRunResponse doPreAuth(ScriptRunRequest request) {
        OA2FunctorFactory functorFactory = getFF((Map) request.getArgs().get(SRE_REQ_CLAIMS),
                (List) request.getArgs().get(SRE_REQ_SCOPES));
        OA2ClientFunctorScriptsFactory<OA2ClientFunctorScripts> ff = getScriptFactory(functorFactory);
        OA2ClientFunctorScripts cc = ff.newInstance();

        if (cc.hasPreProcessing()) {
            ff.setupPreProcessing(cc, config);
            cc.executePreProcessing();
            FlowStates flowStates = (FlowStates) request.getArgs().get(SRE_REQ_FLOW_STATES);
            updateFSValues(flowStates, cc.getPreProcessing().getFunctorMap());
            // Check if we should be returning these as per request.
            ff.createClaimSource(cc, config);
            return createSRR(request, cc.getClaimSource());
        }
        return createSRR(request);
    }

    protected OA2ClientFunctorScriptsFactory<OA2ClientFunctorScripts> getScriptFactory(OA2FunctorFactory ff) {
        return new OA2ClientFunctorScriptsFactory<>(config, ff);
    }

    // This class does not actually have any state to serialize.
    public String serializeState() {
        return "";
    }

    //  JSONObject config;

    public void deserializeState(String state) {
        // no op, because functors are stateless (which is one of their ultimate shortcomings...)
    }

    private ScriptRunResponse doInit(ScriptRunRequest request) {
        OA2FunctorFactory functorFactory = getFF((Map) request.getArgs().get(SRE_REQ_CLAIMS),
                (List) request.getArgs().get(SRE_REQ_SCOPES));
        OA2ClientFunctorScriptsFactory<OA2ClientFunctorScripts> ff = getScriptFactory(functorFactory);
        OA2ClientFunctorScripts cc = ff.newInstance();

        cc.executeRuntime();
        FlowStates flowStates = (FlowStates) request.getArgs().get(SRE_REQ_FLOW_STATES);
        updateFSValues(flowStates, cc.getRuntime().getFunctorMap());
        ff.createClaimSource(cc, config);

        if (request.returnArgs()) {
            Map outMap = new HashMap();
            outMap.putAll(request.getArgs());
        }
        return createSRR(request, cc.getClaimSource());

    }

    public FunctorRuntimeEngine(JSONObject config) {
        super(config);
    }


    protected OA2FunctorFactory getFF(Map claims, List scopes) {
        return new OA2FunctorFactory(claims, scopes);
    }


    /**
     * The contract for this method is that the values of this object (default is all true) will be
     * updated based on the functor map. Unless the values are explicitly changed, they remain.
     * <br/><br/>
     * Unfortunately this has to be static for backwards compatibility.
     * {@link ClaimSource}s can have embedded functor scripts that may update claims and the flow.
     * This was because there was not an actual set of control structures for functors that allowed
     * for state to be shared, etc. Net effect is that that has to remain. With the arrival of QDL,
     * there is never a need to have the claim source itself invoke some sort of processing. 
     *
     * @param functorMap
     */
    public static void updateFSValues(FlowStates f, FunctorMap functorMap) {
        f.acceptRequests = findFSValue(functorMap, ACCEPT_REQUESTS, f.acceptRequests);
        f.accessToken = findFSValue(functorMap, ACCESS_TOKEN, f.accessToken);
        f.getCert = findFSValue(functorMap, GET_CERT, f.getCert);
        f.getClaims = findFSValue(functorMap, GET_CLAIMS, f.getClaims);
        f.idToken = findFSValue(functorMap, ID_TOKEN, f.idToken);
        f.refreshToken = findFSValue(functorMap, REFRESH_TOKEN, f.refreshToken);
        f.userInfo = findFSValue(functorMap, USER_INFO, f.userInfo);
    }

    protected static boolean findFSValue(FunctorMap functorMap, FlowType type, boolean previousValue) {
        if (functorMap.containsKey(type.getValue())) {
            JFunctor jf = functorMap.get(type.getValue()).get(0);
            return (Boolean) jf.getResult();
        }
        return previousValue; //default
    }


}
