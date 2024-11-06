package org.oa4mp.server.loader.oauth2.state;

import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.functor.FunctorRuntimeEngine;
import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.loader.oauth2.storage.transactions.OA2ServiceTransaction;
import org.oa4mp.server.loader.oauth2.storage.tx.TXRecord;
import org.oa4mp.server.loader.oauth2.storage.vi.VirtualIssuer;
import org.oa4mp.server.loader.qdl.scripting.OA2State;
import org.oa4mp.server.loader.qdl.scripting.QDLRuntimeEngine;
import org.qdl_lang.evaluate.MetaEvaluator;
import org.qdl_lang.evaluate.OpEvaluator;
import org.qdl_lang.functions.FStack;
import org.qdl_lang.module.MIStack;
import org.qdl_lang.module.MTStack;
import org.qdl_lang.state.State;
import org.qdl_lang.state.StateUtils;
import org.qdl_lang.variables.VStack;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunRequest;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse;
import edu.uiuc.ncsa.security.util.scripting.ScriptRuntimeEngine;
import net.sf.json.JSONObject;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/12/20 at  1:36 PM
 */
public class ScriptRuntimeEngineFactory {
    public static ScriptRuntimeEngine createRTE(OA2SE oa2SE, OA2ServiceTransaction transaction, TXRecord txRecord, JSONObject config) {
        // note: No QDL tag means no scripting for QDL even if there is an environment configured.
        // This is because there is nothing to execute so no reason to incur the overhead of creating it.
        if (config.containsKey(OA2ClientFunctorScriptsUtil.CLAIMS_KEY)) {
            return new FunctorRuntimeEngine(config);
        }

        OA2Client oa2Client = (OA2Client) transaction.getClient();
/*        if(!oa2Client.hasScript()){
            return null; // Only create QDL runtime environment if there is a reason to do so.
        }*/

        if (oa2SE.getQDLEnvironment() == null || !oa2SE.getQDLEnvironment().isEnabled()) {
            oa2SE.getMyLogger().warn("*********************************");
            oa2SE.getMyLogger().warn("* QDL scripting detected, but   * ");
            oa2SE.getMyLogger().warn("* QDL scripts cannot be run.    *");
            oa2SE.getMyLogger().warn("* No/invalid runtime engine has *");
            oa2SE.getMyLogger().warn("* been configured.              *");
            oa2SE.getMyLogger().warn("*********************************");
        } else {
            if (!StateUtils.isFactorySet()) {
                StateUtils.setFactory(new StateUtils() {
                    @Override
                    public State create() {
                        OA2State ss= new OA2State(
                                new VStack(),
                                new OpEvaluator(),
                                MetaEvaluator.getInstance(),
                                new FStack(),
                                new MTStack(),
                                new MIStack(),
                                null, // no logging at least for now
                                true,
                                true,
                                false,
                                true,
                                null); // default in server mode, but can be overridden later
                        ss.setTransaction(transaction);
                        ss.setOa2se(oa2SE);
                        ss.setTxRecord(txRecord);
                        return ss;
                    }
                });
            }
            QDLRuntimeEngine qrt = new QDLRuntimeEngine(oa2SE.getQDLEnvironment(), transaction);
            qrt.setConfigToCS(transaction.getConfigToCS());
            OA2State state = qrt.getState();
            state.setOa2se(oa2SE);
            VirtualIssuer vo = oa2SE.getVI(oa2Client.getIdentifier());
            if (vo != null) {
                state.setJsonWebKeys(vo.getJsonWebKeys());
            } else {
                state.setJsonWebKeys(oa2SE.getJsonWebKeys());
            }
            state.setTransaction(transaction);
            state.setTxRecord(txRecord);
            state.setLogger(oa2SE.getMyLogger()); // This lets scripts write to the log.
            state.setStrictACLs(oa2SE.isQdlStrictACLs());
            return qrt;
        }
        return null;
    }

    public static ScriptRuntimeEngine createRTE(OA2SE oa2SE, OA2ServiceTransaction transaction, JSONObject config) {
        return createRTE(oa2SE, transaction, null, config);
    }


    public static class NoOpRuntimeEngine extends ScriptRuntimeEngine {
        public NoOpRuntimeEngine() {

        }

        @Override
        public String serializeState() {
            return "";
        }

        @Override
        public String serializeState(String version) {
            return null;
        }

        @Override
        public void deserializeState(String state, String version) {

        }

        // we need exactly one of these.
        public final static ScriptRunResponse srr = new ScriptRunResponse(null, null, ScriptRunResponse.RC_NOT_RUN);

        @Override
        public ScriptRunResponse run(ScriptRunRequest request) {
            return srr;
        }
    }
}
