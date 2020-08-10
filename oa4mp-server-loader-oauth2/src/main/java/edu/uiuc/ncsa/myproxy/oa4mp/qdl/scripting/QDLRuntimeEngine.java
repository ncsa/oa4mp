package edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.FlowStates2;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.FlowType;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.ScriptRuntimeEngineFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims.ConfigtoCS;
import edu.uiuc.ncsa.qdl.config.QDLConfigurationLoaderUtils;
import edu.uiuc.ncsa.qdl.config.QDLEnvironment;
import edu.uiuc.ncsa.qdl.evaluate.MetaEvaluator;
import edu.uiuc.ncsa.qdl.evaluate.OpEvaluator;
import edu.uiuc.ncsa.qdl.exceptions.QDLException;
import edu.uiuc.ncsa.qdl.module.ModuleMap;
import edu.uiuc.ncsa.qdl.scripting.Scripts;
import edu.uiuc.ncsa.qdl.state.ImportManager;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.state.StateUtils;
import edu.uiuc.ncsa.qdl.state.SymbolStack;
import edu.uiuc.ncsa.qdl.statements.FunctionTable;
import edu.uiuc.ncsa.qdl.variables.StemVariable;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.ScriptingConstants;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.util.scripting.ScriptInterface;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunRequest;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse;
import edu.uiuc.ncsa.security.util.scripting.ScriptRuntimeEngine;
import net.sf.json.JSON;
import net.sf.json.JSONObject;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.FlowType.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/12/20 at  9:29 AM
 */
public class QDLRuntimeEngine extends ScriptRuntimeEngine implements ScriptingConstants {
    public static String CONFIG_TAG = "qdl";
    public static String SCRIPTS_TAG = "scripts";

    public QDLRuntimeEngine(QDLEnvironment qe) {
        this.qe = qe;
        init();
        setInitialized(false);

    }

    public QDLRuntimeEngine(QDLEnvironment qe, JSONObject config) {
        this.qe = qe;
        init();
        setInitialized(true);
    }

    public QDLEnvironment getQE() {
        return qe;
    }

    public void setQE(QDLEnvironment qe) {
        this.qe = qe;
    }

    // {"qdl": { "code": ["claims.debug:='test';"], "xmd": {"exec_phase": "pre_auth"}}}
    // {"qdl": { "run": "vfs#/scripts/test0.qdl", "xmd": {"exec_phase": "pre_auth"}}}
    QDLEnvironment qe;

    /**
     * The structure of the configuration file (for backwards compatibility) is
     * <pre>
     *     {"config":[comments],
     *       "qdl" : {"scripts" : [{"script":{...}}, {"script":{...}},...]}
     *      }
     *
     * </pre>
     * The assumption is that this is handed the qdl config object and can start pulling it apart at
     * that level.
     */
    protected void init() {
//        setScriptSet(QDLJSONConfigUtil.readScriptSet(config));  // <- old way
        //setScriptSet(AnotherJSONUtil.createScripts(config)); // <- new way
        SymbolStack stack = new SymbolStack();
        state = new State(ImportManager.getResolver(),
                stack,
                new OpEvaluator(),
                MetaEvaluator.getInstance(),
                new FunctionTable(),
                new ModuleMap(),
                null, // no logging at least for now
                true);// enable server mode.
        state.getOpEvaluator().setNumericDigits(qe.getNumericDigits());
        if (qe != null && qe.isEnabled()) {
            try {
                QDLConfigurationLoaderUtils.setupVFS(qe, state);
                QDLConfigurationLoaderUtils.setupModules(qe, state);
                QDLConfigurationLoaderUtils.runBootScript(qe, state);
            } catch (Throwable throwable) {
                throwable.printStackTrace();
            }
        }
    }

    @Override
    public String serializeState() {
        try {
            return StateUtils.saveb64(state);
        } catch (IOException e) {
            e.printStackTrace();
            throw new QDLException("Error: could not serialize the state:" + e.getMessage(), e);
        }
    }

    State state;

    @Override
    public void deserializeState(String state) {
        if (state == null || state.isEmpty()) return;
        try {
            this.state = StateUtils.loadb64(state);
        } catch (Throwable e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }
            e.printStackTrace();
            throw new QDLException("Error deserializing state", e);
        }
    }

    // Idiom. If no scripts at all, then just return null;
    protected ScriptInterface getScript(String phase) {
        if (getScriptSet() == null) return null;
        return getScriptSet().get(Scripts.EXEC_PHASE, phase);
    }

    @Override
    public ScriptRunResponse run(ScriptRunRequest request) {
        ScriptInterface s = null;

        switch (request.getAction()) {
            case SRE_EXEC_INIT:
                s = getScript(SRE_EXEC_INIT);
                break;
            case SRE_PRE_AUTH:
                s = getScript(SRE_PRE_AUTH);
                break;
            case SRE_POST_AT:
                s = getScript(SRE_POST_AT);
                break;
            case SRE_POST_AUTH:
                s = getScript(SRE_POST_AUTH);
                break;
            case SRE_PRE_AT:
                s = getScript(SRE_PRE_AT);
                break;
            case SRE_PRE_REFRESH:
                s = getScript(SRE_PRE_REFRESH);
                break;
            case SRE_POST_REFRESH:
                s = getScript(SRE_POST_REFRESH);
                break;
        }
        if (s == null) {
            return noOpSRR();
        }
        //
        setupState(request);
        s.execute(state);
        return createSRR();
    }

    protected String FLOW_STATE_VAR = "flow_states.";
    protected String CLAIMS_VAR = "claims.";
    protected String ACCESS_TOKEN_VAR = "access_token.";
    protected String SCOPES_VAR = "scopes.";
    protected String EXTENDED_ATTRIBUTES_VAR = "xas.";
    protected String AUDIENCE_VAR = "audience.";
    protected String CLAIM_SOURCES_VAR = "claim_sources.";


    /**
     * This injects the values in the request in to the current state so they are available.
     *
     * @param req
     */
    protected void setupState(ScriptRunRequest req) {
        FlowStates2 flowStates = (FlowStates2) req.getArgs().get(SRE_REQ_FLOW_STATES);
        state.getSymbolStack().setValue(FLOW_STATE_VAR, toStem(flowStates));

        JSONObject claims = (JSONObject) req.getArgs().get(SRE_REQ_CLAIMS);
        StemVariable claimStem = new StemVariable();
        claimStem.fromJSON(claims);
        state.getSymbolStack().setValue(CLAIMS_VAR, claimStem);

        if (req.getArgs().containsKey(SRE_REQ_ACCESS_TOKEN)) {
            JSONObject at = (JSONObject) req.getArgs().get(SRE_REQ_ACCESS_TOKEN);
            StemVariable atStem = new StemVariable();
            atStem.fromJSON(at);
            state.getSymbolStack().setValue(ACCESS_TOKEN_VAR, atStem);

        }
        List<String> scopes = (List<String>) req.getArgs().get(SRE_REQ_SCOPES);
        if(scopes != null && !scopes.isEmpty()) {
            // It is possible for a minimal OAuth 2 client to have no scopes.
            state.getSymbolStack().setValue(SCOPES_VAR, toStem(scopes));
        }else{
            state.getSymbolStack().setValue(SCOPES_VAR, new StemVariable());

        }

        List<String> audience = (List<String>) req.getArgs().get(SRE_REQ_AUDIENCE);
        if(audience != null && !audience.isEmpty()) {
            state.getSymbolStack().setValue(AUDIENCE_VAR, toStem(audience));
        }else{
            state.getSymbolStack().setValue(AUDIENCE_VAR, new StemVariable());
        }

        Object eas = req.getArgs().get(SRE_REQ_EXTENDED_ATTRIBUTES);
        if (eas != null && (eas instanceof JSONObject)) {
            StemVariable eaStem = new StemVariable();
            eaStem.fromJSON((JSONObject) eas);
            state.getSymbolStack().setValue(EXTENDED_ATTRIBUTES_VAR, eaStem);
        }else{
            state.getSymbolStack().setValue(EXTENDED_ATTRIBUTES_VAR, new StemVariable());
        }

        StemVariable sources = new StemVariable();
        int i = 0;
        for (ClaimSource source : (List<ClaimSource>) req.getArgs().get(SRE_REQ_CLAIM_SOURCES)) {
            sources.put(i + ".", ConfigtoCS.convert(source));
            i++;
        }
        state.getSymbolStack().setValue(CLAIM_SOURCES_VAR, sources);
    }

    public StemVariable toStem(List<String> scopes) {
        StemVariable scopeStem = new StemVariable();
        for (int i = 0; i < scopes.size(); i++) {
            String index = Integer.toString(i);
            scopeStem.put(index, scopes.get(i));
        }
        return scopeStem;
    }

    public List<String> toScopes(StemVariable arg) {
        ArrayList<String> scopes = new ArrayList<>();
        for (String key : arg.keySet()) {
            scopes.add(arg.getString(key));
        }
        return scopes;
    }

    protected List<ClaimSource> toSources(StemVariable stemVariable) {
        ArrayList<ClaimSource> claimSources = new ArrayList<>();

        for (int i = 0; i < stemVariable.size(); i++) {
            String index = Integer.toString(i) + "."; // make sure its a stem
            // if they added extra stuff, skip it. 
            if (stemVariable.containsKey(index)) {
                StemVariable cfg = (StemVariable) stemVariable.get(index);
                claimSources.add(ConfigtoCS.convert(cfg));
            }
        }
        return claimSources;
    }

    public StemVariable toStem(FlowStates2 flowStates) {
        StemVariable stemVariable = new StemVariable();
        stemVariable.put(getGTName(ACCEPT_REQUESTS), flowStates.acceptRequests);
        stemVariable.put(getGTName(ACCESS_TOKEN), flowStates.accessToken);
        stemVariable.put(getGTName(GET_CERT), flowStates.getCert);
        stemVariable.put(getGTName(GET_CLAIMS), flowStates.getClaims);
        stemVariable.put(getGTName(ID_TOKEN), flowStates.idToken);
        stemVariable.put(getGTName(REFRESH_TOKEN), flowStates.refreshToken);
        stemVariable.put(getGTName(USER_INFO), flowStates.userInfo);

        return stemVariable;
    }

    protected String getGTName(FlowType type) {
        return type.getValue().substring(1); // chop off lead "$"
    }

    public FlowStates2 toFS(StemVariable stem) {
        FlowStates2 f = new FlowStates2();
        f.acceptRequests = stem.getBoolean(getGTName(ACCEPT_REQUESTS));
        f.accessToken = stem.getBoolean(getGTName(ACCESS_TOKEN));
        f.getCert = stem.getBoolean(getGTName(GET_CERT));
        f.getClaims = stem.getBoolean(getGTName(GET_CLAIMS));
        f.idToken = stem.getBoolean(getGTName(ID_TOKEN));
        f.refreshToken = stem.getBoolean(getGTName(REFRESH_TOKEN));
        f.userInfo = stem.getBoolean(getGTName(USER_INFO));
        return f;
    }


    protected ScriptRunResponse noOpSRR() {
        return ScriptRuntimeEngineFactory.NoOpRuntimeEngine.srr;
    }

    protected ScriptRunResponse createSRR() {
        Map respMap = new HashMap();
        StemVariable flowStem = (StemVariable) state.getValue(FLOW_STATE_VAR);

        respMap.put(SRE_REQ_FLOW_STATES, toFS(flowStem));
        respMap.put(SRE_REQ_CLAIM_SOURCES, toSources((StemVariable) state.getValue(CLAIM_SOURCES_VAR)));
        respMap.put(SRE_REQ_SCOPES, toScopes((StemVariable) state.getValue(SCOPES_VAR)));
        respMap.put(SRE_REQ_EXTENDED_ATTRIBUTES, ((StemVariable) state.getValue(EXTENDED_ATTRIBUTES_VAR)).toJSON());
        respMap.put(SRE_REQ_AUDIENCE, toScopes((StemVariable) state.getValue(AUDIENCE_VAR)));
        StemVariable stemClaims = (StemVariable) state.getValue(CLAIMS_VAR);
        JSON j = stemClaims.toJSON();
        if (j.isArray()) {
            throw new NFWException("Internal error: The returned claims object was not a JSON Object.");
        }
        respMap.put(SRE_REQ_CLAIMS, j);
        //runResponse.
        return new ScriptRunResponse("ok", respMap, ScriptRunResponse.RC_OK);
    }
}
