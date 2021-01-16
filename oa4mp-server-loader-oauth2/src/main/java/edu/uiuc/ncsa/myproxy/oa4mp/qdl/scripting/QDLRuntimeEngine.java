package edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.FlowStates2;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.FlowType;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.ScriptRuntimeEngineFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXRecord;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims.ConfigtoCS;
import edu.uiuc.ncsa.qdl.config.QDLConfigurationLoaderUtils;
import edu.uiuc.ncsa.qdl.config.QDLEnvironment;
import edu.uiuc.ncsa.qdl.exceptions.QDLException;
import edu.uiuc.ncsa.qdl.scripting.Scripts;
import edu.uiuc.ncsa.qdl.state.StateUtils;
import edu.uiuc.ncsa.qdl.variables.QDLNull;
import edu.uiuc.ncsa.qdl.variables.StemVariable;
import edu.uiuc.ncsa.qdl.xml.XMLUtils;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.ScriptRuntimeException;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.ScriptingConstants;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.util.scripting.ScriptInterface;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunRequest;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse;
import edu.uiuc.ncsa.security.util.scripting.ScriptRuntimeEngine;
import net.sf.json.JSON;
import net.sf.json.JSONObject;
import org.apache.commons.codec.binary.Base64;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamWriter;
import java.io.*;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.FlowType.*;
import static edu.uiuc.ncsa.qdl.variables.StemVariable.STEM_INDEX_MARKER;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/12/20 at  9:29 AM
 */
public class QDLRuntimeEngine extends ScriptRuntimeEngine implements ScriptingConstants {
    public static String CONFIG_TAG = "qdl";
    public static String SCRIPTS_TAG = "scripts";

    public QDLRuntimeEngine(QDLEnvironment qe, OA2ServiceTransaction transaction) {
        this.qe = qe;
        init(transaction);
        setInitialized(false);
    }

    @Override
    public OA2State getState() {
        return (OA2State) state; // only thing it can create
    }

/*
    public QDLRuntimeEngine(QDLEnvironment qe, JSONObject config) {
        this.qe = qe;
        init();
        setInitialized(true);
    }
*/

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
    protected void init(OA2ServiceTransaction transaction) {
        state = (OA2State) StateUtils.newInstance();
        if (transaction.hasScriptState()) {
            try {
                deserializeState(transaction.getScriptState());
            }catch(Throwable t){
                DebugUtil.trace(this, "Could not deserialize stored transaction state:" + t.getMessage());
                if(getState().getOa2se() != null){
                    getState().getOa2se().getMyLogger().warn("Could not deserialize stored transaction state:" + t.getMessage());
                }
            }
        }
        state.setServerMode(qe.isServerModeOn());
        state.getOpEvaluator().setNumericDigits(qe.getNumericDigits());
        state.setScriptPaths(qe.getScriptPath());  // Be sure script paths are read.
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
            StringWriter w = new StringWriter();
            XMLOutputFactory xof = XMLOutputFactory.newInstance();
            XMLStreamWriter xsw = xof.createXMLStreamWriter(w);

            state.toXML(xsw);
            String xml2 = XMLUtils.prettyPrint(w.toString()); // We do this because whitespace matters. This controls it.
            DebugUtil.trace(this, "\nSerialized state\n:" + xml2);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            GZIPOutputStream gzipOutputStream = new GZIPOutputStream(baos);
            gzipOutputStream.write(xml2.getBytes("UTF-8"));
            gzipOutputStream.flush();
            gzipOutputStream.close();
            xsw.close();
            return Base64.encodeBase64String(baos.toByteArray());


//            return XMLUtils.prettyPrint(w.toString());
            // Old way:
            //   return StateUtils.saveb64(state);
        } catch (Throwable e) {
            e.printStackTrace();
            throw new QDLException("Error: could not serialize the state:" + e.getMessage(), e);
        }
    }

    OA2State state;

    @Override
    public void deserializeState(String rawState) {
        if (rawState == null || rawState.isEmpty()) return;
        try {
            byte[] xx = Base64.decodeBase64(rawState);
            ByteArrayInputStream bais = new ByteArrayInputStream(xx);
            // Reconstruct the XML as a string, preserving whitespace.
            GZIPInputStream gzipInputStream = new GZIPInputStream(bais, 65536);
            Reader r = new InputStreamReader(gzipInputStream);
/*
            Debug stuff to recreate the XML exactly and print it out. Otherwise it is
            squirreled away inside a zgip stream someplace.
*/
/*
            BufferedReader br = new BufferedReader(r);
            StringBuffer stringBuffer = new StringBuffer();
            String lineIn = br.readLine();
            while(lineIn != null){
                stringBuffer.append(lineIn + "\n");
                System.out.println(lineIn);
                lineIn = br.readLine();
            }
            DebugUtil.trace(this, "De-zipped XML:\n" + stringBuffer.toString());
            StringReader reader = new StringReader(stringBuffer.toString());
*/
            XMLInputFactory xmlif = XMLInputFactory.newInstance();
            XMLEventReader xer = xmlif.createXMLEventReader(r);
            // Moar debug, if using the string, replace preceeding line with this.
            // XMLEventReader xer = xmlif.createXMLEventReader(reader);
            // state = (OA2State) StateUtils.newInstance();
            state.fromXML(xer, null); // No XProperties in serialization.
            xer.close();
            // Old way
            // this.state = (OA2State) StateUtils.loadb64(state);
        } catch (Throwable e) {
            DebugUtil.trace(this, "error deserializing state", e);
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }
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
            case SRE_PRE_EXCHANGE:
                s = getScript(SRE_PRE_EXCHANGE);
                break;
            case SRE_POST_EXCHANGE:
                s = getScript(SRE_POST_EXCHANGE);
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

    /*
    Note that these are the names of the variable in the QDL symbol table and since they are stems
    they must end with periods.
     */
    protected String SYS_ERR_VAR = "sys_err" + STEM_INDEX_MARKER;
    protected String SYS_ERR_OK = "ok";
    protected String SYS_ERR_MESSAGE = "message";
    protected String FLOW_STATE_VAR = "flow_states" + STEM_INDEX_MARKER;
    protected String CLAIMS_VAR = "claims" + STEM_INDEX_MARKER;
    protected String ACCESS_TOKEN_VAR = "access_token" + STEM_INDEX_MARKER;
    protected String SCOPES_VAR = "scopes" + STEM_INDEX_MARKER;
    protected String EXTENDED_ATTRIBUTES_VAR = "xas" + STEM_INDEX_MARKER;
    protected String AUDIENCE_VAR = "audience" + STEM_INDEX_MARKER;
    protected String TX_SCOPES_VAR = "tx_scopes" + STEM_INDEX_MARKER;
    protected String TX_AUDIENCE_VAR = "tx_audience" + STEM_INDEX_MARKER;
    protected String TX_RESOURCE_VAR = "tx_resource" + STEM_INDEX_MARKER;
    protected String CLAIM_SOURCES_VAR = "claim_sources" + STEM_INDEX_MARKER;
    protected String ACCESS_CONTROL = "access_control" + STEM_INDEX_MARKER;

    /**
     * This injects the values in the request in to the current state so they are available.
     *
     * @param req
     */
    protected void setupState(ScriptRunRequest req) {

        state.getSymbolStack().setValue(Scripts.EXEC_PHASE, req.getAction()); // set what is being executed

        state.getSymbolStack().setValue(SYS_ERR_VAR, new StemVariable()); // just an empty one.
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
        if (scopes != null && !scopes.isEmpty()) {
            // It is possible for a minimal OAuth 2 client to have no scopes.
            state.getSymbolStack().setValue(SCOPES_VAR, listToStem(scopes));
        } else {
            state.getSymbolStack().setValue(SCOPES_VAR, new StemVariable());

        }

        List<String> audience = (List<String>) req.getArgs().get(SRE_REQ_AUDIENCE);
        if (audience != null && !audience.isEmpty()) {
            state.getSymbolStack().setValue(AUDIENCE_VAR, listToStem(audience));
        } else {
            state.getSymbolStack().setValue(AUDIENCE_VAR, new StemVariable());
        }

        Object eas = req.getArgs().get(SRE_REQ_EXTENDED_ATTRIBUTES);
        if (eas != null && (eas instanceof JSONObject)) {
            StemVariable eaStem = new StemVariable();
            eaStem.fromJSON((JSONObject) eas);
            state.getSymbolStack().setValue(EXTENDED_ATTRIBUTES_VAR, eaStem);
        } else {
            state.getSymbolStack().setValue(EXTENDED_ATTRIBUTES_VAR, new StemVariable());
        }

        StemVariable sources = new StemVariable();
        int i = 0;
        // not every handler or request has claim sources.
        // Some handlers inject them later because they need more state than is available.
        if (req.getArgs().containsKey(SRE_REQ_CLAIM_SOURCES)) {
            for (ClaimSource source : (List<ClaimSource>) req.getArgs().get(SRE_REQ_CLAIM_SOURCES)) {
                sources.put(i + ".", ConfigtoCS.convert(source));
                i++;
            }
        }
        state.getSymbolStack().setValue(CLAIM_SOURCES_VAR, sources);
        // Now do access control
        // gives variable
        // access_control.
        // access_control.client_id == id of calling client
        // access_control.admins. == list of administrators for this client.
        StemVariable acl = new StemVariable();
        acl.put("client_id", state.getClientID().toString());
        // Convert to a list of string.
        ArrayList<Object> adminIDs = new ArrayList<>();
        for (Identifier id : state.getAdminIDs()) {
            adminIDs.add(id.toString());
        }
        StemVariable adminStem = new StemVariable();
        adminStem.addList(adminIDs);
        acl.put("admins.", adminStem);
        state.getSymbolStack().setValue(ACCESS_CONTROL, acl);
        if (state.getTxRecord() != null) {
            // following block always sets these variables even if there is nothing sent.
            // In this way, it is easier to use them in scripting rather than having to check
            // if they exist.
            TXRecord txr = state.getTxRecord();
            StemVariable txScopes = new StemVariable();
            if (txr.hasScopes()) {
                txScopes.addList(txr.getScopes());
            }
            state.getSymbolStack().setValue(TX_SCOPES_VAR, txScopes);
            StemVariable txAud = new StemVariable();
            if (txr.hasAudience()) {
                txAud.addList(txr.getAudience());
            }
            state.getSymbolStack().setValue(TX_AUDIENCE_VAR, txAud);
            StemVariable txRes = new StemVariable();
            if (txr.hasResources()) {
                for (URI uri : txr.getResource()) {

                    txRes.listAppend(uri.toString());
                }
            }
            state.getSymbolStack().setValue(TX_RESOURCE_VAR, txRes);
        }


    }

    public StemVariable listToStem(List<String> scopes) {
        StemVariable scopeStem = new StemVariable();
        for (int i = 0; i < scopes.size(); i++) {
            String index = Integer.toString(i);
            scopeStem.put(index, scopes.get(i));
        }
        return scopeStem;
    }

    public List<String> stemToList(StemVariable arg) {
        ArrayList<String> scopes = new ArrayList<>();
        for (String key : arg.keySet()) {
            scopes.add(arg.getString(key));
        }
        return scopes;
    }

    protected List<ClaimSource> toSources(StemVariable stemVariable) {
        ArrayList<ClaimSource> claimSources = new ArrayList<>();

        for (int i = 0; i < stemVariable.size(); i++) {
            // String index = Integer.toString(i) + "."; // make sure its a stem
            // if they added extra stuff, skip it. 
            if (stemVariable.containsKey((long) i)) {
                StemVariable cfg = (StemVariable) stemVariable.get((long) i);
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
        stemVariable.put(getGTName(AT_DO_TEMPLATES), flowStates.at_do_templates);

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
        f.at_do_templates = stem.getBoolean(getGTName(AT_DO_TEMPLATES));
        return f;
    }


    protected ScriptRunResponse noOpSRR() {
        return ScriptRuntimeEngineFactory.NoOpRuntimeEngine.srr;
    }

    protected ScriptRunResponse createSRR() {
        Object x = state.getValue(SYS_ERR_VAR);
        if (x != null && x instanceof StemVariable) {
            StemVariable sysErr = (StemVariable) x;
            if (sysErr.containsKey(SYS_ERR_OK) && !sysErr.getBoolean(SYS_ERR_OK)) {
                String message = sysErr.getString(SYS_ERR_MESSAGE);
                throw new ScriptRuntimeException(message == null ? "(no message)" : message);
            }
        }
        Map respMap = new HashMap();
        StemVariable flowStem = (StemVariable) state.getValue(FLOW_STATE_VAR);

        respMap.put(SRE_REQ_FLOW_STATES, toFS(flowStem));
        respMap.put(SRE_REQ_CLAIM_SOURCES, toSources((StemVariable) state.getValue(CLAIM_SOURCES_VAR)));
        respMap.put(SRE_REQ_SCOPES, stemToList((StemVariable) state.getValue(SCOPES_VAR)));
        respMap.put(SRE_REQ_EXTENDED_ATTRIBUTES, ((StemVariable) state.getValue(EXTENDED_ATTRIBUTES_VAR)).toJSON());
        if (state.getValue(ACCESS_TOKEN_VAR) != null) {
            respMap.put(SRE_REQ_ACCESS_TOKEN, ((StemVariable) state.getValue(ACCESS_TOKEN_VAR)).toJSON());
        }
        respMap.put(SRE_REQ_AUDIENCE, stemToList((StemVariable) state.getValue(AUDIENCE_VAR)));
        Object z = state.getValue(CLAIMS_VAR);
        DebugUtil.trace(this, "QDL returned claims from state:" + z);
        StemVariable stemClaims;
        if (z instanceof QDLNull) {
            stemClaims = new StemVariable();
        } else {
            stemClaims = (StemVariable) state.getValue(CLAIMS_VAR);
        }

        JSON j = stemClaims.toJSON();
        if (j.isArray()) {
            throw new NFWException("Internal error: The returned claims object was not a JSON Object.");
        }
        respMap.put(SRE_REQ_CLAIMS, j);
        DebugUtil.trace(this, "QDL updates response map:" + j.toString(1));

        /*
        Now for token exchange stuff
         */
        if (state.isDefined(TX_SCOPES_VAR)) {
            respMap.put(SRE_TX_REQ_SCOPES, stemToList((StemVariable) state.getValue(TX_SCOPES_VAR)));
        }
        if (state.isDefined(TX_AUDIENCE_VAR)) {
            respMap.put(SRE_TX_REQ_AUDIENCE, stemToList((StemVariable) state.getValue(TX_AUDIENCE_VAR)));
        }
        if (state.isDefined(TX_RESOURCE_VAR)) {
            List<String> res = stemToList((StemVariable) state.getValue(TX_RESOURCE_VAR));

            ArrayList<URI> zz = new ArrayList<>();
            for (String r : res) {
                try {
                    zz.add(URI.create(r));
                } catch (Throwable t) {
                    getState().getLogger().warn("Illegal uri in stem conversion for token exchange resources: \"" + r + "\". Skipping");
                }

            }
            respMap.put(SRE_TX_REQ_RESOURCES, zz);
        }
        try {
            // Don't serialize anything the system manages since that may cause confusion later.
            cleanUpState(new String[]{
                    SYS_ERR_VAR,
                    TX_SCOPES_VAR,
                    TX_AUDIENCE_VAR,
                    TX_RESOURCE_VAR,
                    CLAIMS_VAR,
                    CLAIM_SOURCES_VAR,
                    FLOW_STATE_VAR,
                    SCOPES_VAR,
                    EXTENDED_ATTRIBUTES_VAR,
                    ACCESS_TOKEN_VAR,
                    AUDIENCE_VAR,
                    Scripts.EXEC_PHASE

            });

            state.getTransaction().setScriptState(serializeState());
        }catch(Throwable t){
            DebugUtil.trace(this, "Could not serialize stored transaction state:" + t.getMessage());
            if(getState().getOa2se() != null){
                getState().getOa2se().getMyLogger().warn("Could not serialize stored transaction state:" + t.getMessage());
            }
        }
        //runResponse.
        return new ScriptRunResponse("ok", respMap, ScriptRunResponse.RC_OK);
    }
    protected void cleanUpState(String[] varNames){
        for(String varName:varNames) {
            if (state.isDefined(varName)) {
                state.remove(varName);
            }
        }
    }
}
