package edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.FlowStates;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.FlowType;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.ScriptRuntimeEngineFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.OA2QDLLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims.ConfigtoCS;
import edu.uiuc.ncsa.qdl.evaluate.MetaEvaluator;
import edu.uiuc.ncsa.qdl.evaluate.OpEvaluator;
import edu.uiuc.ncsa.qdl.exceptions.QDLException;
import edu.uiuc.ncsa.qdl.module.Module;
import edu.uiuc.ncsa.qdl.module.ModuleMap;
import edu.uiuc.ncsa.qdl.scripting.QDLScript;
import edu.uiuc.ncsa.qdl.scripting.QDLScriptLibrary;
import edu.uiuc.ncsa.qdl.scripting.Scripts;
import edu.uiuc.ncsa.qdl.state.*;
import edu.uiuc.ncsa.qdl.statements.FunctionTable;
import edu.uiuc.ncsa.qdl.util.StemVariable;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.util.scripting.*;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.OA2ClaimsUtil.*;
import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.FlowType.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/12/20 at  9:29 AM
 */
public class QDLRuntimeEngine extends ScriptRuntimeEngine {
    public static String CONFIG_TAG = "config2";
    public static String SCRIPTS_TAG = "scripts";
    public static String QDL_VIRTUAL_FILE_SYSTEM_SCHEME = "qdl-vfs:";


    public QDLRuntimeEngine(JSONObject config) {
        super(config);
        init();
    }

    /**
     * The structure of the configuration file (for backwards compatibility) is
     * <pre>
     *     {"config":[comments],
     *       "config2" : {"scripts" : [{"script":{...}}, {"script":{...}},...]}
     *      }
     *
     * </pre>
     * The assumption is that this is handed the config2 object and can start pulling it apart at
     * that level.
     */
    protected void init() {
        JSONArray array = config.getJSONArray(SCRIPTS_TAG);
        QDLScriptLibrary library = new QDLScriptLibrary(QDL_VIRTUAL_FILE_SYSTEM_SCHEME);
        ScriptSet<QDLScript> scriptSet = new ScriptSet<>();
        for (int i = 0; i < array.size(); i++) {
            QDLScript qdlScript = Scripts.fromJSON(array.getJSONObject(i));
            scriptSet.add(qdlScript);
            library.put(QDL_VIRTUAL_FILE_SYSTEM_SCHEME + qdlScript.getProperties().getString(Scripts.ID), qdlScript);
        }
        setScriptSet(scriptSet);
        SymbolTableImpl symbolTable = new SymbolTableImpl();
        SymbolStack stack = new SymbolStack();
        stack.addParent(symbolTable);
        state = new State(ImportManager.getResolver(),
                stack,
                new OpEvaluator(),
                MetaEvaluator.getInstance(),
                new FunctionTable(),
                new ModuleMap(),
                false);// workspace is never in server mode


        state.addScriptProvider(library); // This means that the set of scripts in the config file now is in a virtual file system
        // add the modules
        OA2QDLLoader loader = new OA2QDLLoader();
        for (Module m : loader.load()) {
            state.addModule(m); // done!
            state.getImportedModules().addImport(m.getNamespace(), m.getAlias());
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

    @Override
    public ScriptRunResponse run(ScriptRunRequest request) {
        ScriptInterface s = null;

        switch (request.getAction()) {
            case SRE_EXEC_INIT:
                s = getScriptSet().get(Scripts.EXEC_PHASE, SRE_EXEC_INIT);
                break;
            case SRE_PRE_AUTH:
                s = getScriptSet().get(Scripts.EXEC_PHASE, SRE_PRE_AUTH);
                break;
            case SRE_POST_AT:
                s = getScriptSet().get(Scripts.EXEC_PHASE, SRE_POST_AT);
                break;
            case SRE_POST_AUTH:
                s = getScriptSet().get(Scripts.EXEC_PHASE, SRE_POST_AUTH);
                break;
            case SRE_PRE_AT:
                s = getScriptSet().get(Scripts.EXEC_PHASE, SRE_PRE_AT);
                break;
        }
        if (s == null) {
            return noOpSRR();
        }

        setupState(request);
        s.execute(state);
        return createSRR();
    }

    protected String FLOW_STATE_VAR = "flow_states.";
    protected String CLAIMS_VAR = "claims.";
    protected String SCOPES_VAR = "scopes.";
    protected String CLAIM_SOURCES_VAR = "claim_sources.";

    protected StemVariable mapToStem(Map map) {
        StemVariable stemVariable = new StemVariable();
        stemVariable.putAll(map);
        return stemVariable;
    }

    /**
     * This injects the values in the request in to the current state so they are available.
     *
     * @param req
     */
    protected void setupState(ScriptRunRequest req) {
        FlowStates flowStates = (FlowStates) req.getArgs().get(SRE_REQ_FLOW_STATES);
        state.getSymbolStack().setValue(FLOW_STATE_VAR, toStem(flowStates));

        JSONObject claims = (JSONObject) req.getArgs().get(SRE_REQ_CLAIMS);
        StemVariable claimStem = new StemVariable();
        if (claims != null) {
            claimStem.putAll(claims);
        }
        state.getSymbolStack().setValue(CLAIMS_VAR, claimStem);

        List<String> scopes = (List<String>) req.getArgs().get(SRE_REQ_SCOPES);
        state.getSymbolStack().setValue(SCOPES_VAR, toStem(scopes));

        StemVariable sources = new StemVariable();
        int i = 0;
        for(ClaimSource source : (List<ClaimSource>) req.getArgs().get(SRE_REQ_CLAIM_SOURCES)){
            sources.put(i + ".", ConfigtoCS.convert(source));
            i++;
        }
        state.getSymbolStack().setValue(CLAIM_SOURCES_VAR,sources);
    }

    public StemVariable toStem(List<String> scopes) {
        StemVariable scopeStem = new StemVariable();
        for(int i = 0; i < scopes.size(); i++){
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
            String index = Integer.toString(i)+"."; // make sure its a stem
            // if they added extra stuff, skip it. 
            if (stemVariable.containsKey(index)) {
                StemVariable cfg = (StemVariable) stemVariable.get(index);
                claimSources.add(ConfigtoCS.convert(cfg));
            }
        }
        return claimSources;
    }

    public StemVariable toStem(FlowStates flowStates) {
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

    public FlowStates toFS(StemVariable stem) {
        FlowStates f = new FlowStates();
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
        JSONObject jsonObject = new JSONObject();
        jsonObject.putAll((StemVariable) state.getValue(CLAIMS_VAR));
        respMap.put(SRE_REQ_CLAIMS, jsonObject);
        //runResponse.
        return new ScriptRunResponse("ok", respMap, ScriptRunResponse.RC_OK);
    }
}
