package org.oa4mp.server.loader.qdl.claims;

import org.oa4mp.server.loader.oauth2.claims.AbstractPayloadConfig;
import org.oa4mp.server.loader.oauth2.claims.IDTokenHandler;
import org.oa4mp.server.loader.qdl.scripting.OA2State;
import org.qdl_lang.exceptions.BadArgException;
import org.qdl_lang.extensions.QDLMetaModule;
import org.qdl_lang.state.State;
import org.qdl_lang.variables.QDLStem;
import net.sf.json.JSONObject;
import org.qdl_lang.variables.values.BooleanValue;
import org.qdl_lang.variables.values.QDLValue;

import java.util.ArrayList;
import java.util.List;

import static edu.uiuc.ncsa.security.util.scripting.ScriptingConstants.*;
import static org.qdl_lang.variables.values.QDLValue.asQDLValue;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/12/20 at  6:12 AM
 */
public class IDTokenInitializer implements QDLMetaModule {
    public static String ID_TOKEN_INIT_METHOD = "id_init";
    public static String ID_TOKEN_FINISH_METHOD = "id_finish";
    public static String ID_TOKEN_REFRESH_METHOD = "id_refresh";
    public static String ID_TOKEN_CHECK_CLAIM_METHOD = "id_check_claim";

    IDTokenHandler idTokenHandler;

    protected IDTokenHandler getidTokenHandler() {
        return idTokenHandler;
    }

    boolean isInit = false;

    public abstract class IDMethods extends TokenHandlerMethod {
        public IDMethods(OA2State oa2State) {
            super(oa2State);
        }

        protected Boolean isQuery(String execPhase) {
            boolean isQuery = false;
            switch (execPhase) {
                case SRE_PRE_AUTH:
                case SRE_POST_AUTH:
                case SRE_EXEC_INIT:
                    isQuery = true;
                    break;
                default:
                    isQuery = false;
            }
            return isQuery;
        }

        @Override
        protected AbstractPayloadConfig getPayloadConfig() {
            return getClient().getIDTokenConfig();
        }

        public abstract void doMethod(String execPhase) throws Throwable;

        @Override
        public QDLValue evaluate(QDLValue[] objects, State state) {
            super.evaluate(objects, state);
            QDLStem idtoken = checkArg(objects, getName(), 0);
            QDLStem output = new QDLStem();
            if (idTokenHandler == null) {
                idTokenHandler = new IDTokenHandler(getPayloadHandlerConfig());
            }
            if (1 < objects.length) {
                throw new IllegalArgumentException(" Missing second argument must be the execution phase.");
            }
            if (!(objects[1].isString())) {
                throw new BadArgException(" The second argument must be a string.",1);

            }
            String execPhase = objects[1].asString();
            getidTokenHandler().setUserMetaData((JSONObject) idtoken.toJSON());
            try {
                doMethod(execPhase);
            } catch (Throwable throwable) {
                handleException(throwable);
            }

            output.fromJSON(getidTokenHandler().getUserMetaData());
            return asQDLValue(output);
        }

    }


    public class idInit extends IDMethods {
        public idInit(OA2State oa2State) {
            super(oa2State);
        }

        @Override
        public String getName() {
            return ID_TOKEN_INIT_METHOD;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public void doMethod(String execPhase) throws Throwable {
            getidTokenHandler().init();
            isInit = true;
        }


        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            if (argCount == 1) {
                doxx.add(getName() + "(id_token.) - initialize an id token with all the standard claims.");
                doxx.add("You should invoke this before any other processing to be sure that things like the issued at timestamp are accurate.");
                doxx.add("Also, various internal things (such as global claims processing at the server level) are invoked. Always call this if you ");
                doxx.add("are going to roll your own id token.");
                doxx.add("See also: " + ID_TOKEN_FINISH_METHOD);
            }
            return doxx;
        }
    }

    public class idFinish extends IDMethods {
        public idFinish(OA2State oa2State) {
            super(oa2State);
        }

        @Override
        public String getName() {
            return ID_TOKEN_FINISH_METHOD;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public void doMethod(String execPhase) throws Throwable {
            if (!isInit) {
                throw new IllegalStateException(" You must run init first.");
            }
            getidTokenHandler().finish(execPhase);
        }


        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            if (argCount == 1) {
                doxx.add(getName() + "(id_token.) - finish any setup that is required for this token, e.g., the expiration time.");
                doxx.add("This is the last thing that you should invoke before returning the id token.");
                doxx.add("See also: " + ID_TOKEN_INIT_METHOD);
            }
            return doxx;
        }
    }

    public class idRefresh extends IDMethods {
        public idRefresh(OA2State oa2State) {
            super(oa2State);
        }

        @Override
        public String getName() {
            return ID_TOKEN_REFRESH_METHOD;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public void doMethod(String execPhase) throws Throwable {
            if (!isInit) {
                throw new IllegalStateException(" You must run init first.");
            }

            getidTokenHandler().refresh();
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            if (argCount == 1) {
                doxx.add(getName() + "(id_token.) - refresh the id token");
                doxx.add("See also: " + ID_TOKEN_INIT_METHOD + ", " + ID_TOKEN_FINISH_METHOD);
            }
            return doxx;
        }
    }

    public class idCheckClaims extends IDMethods {
        public idCheckClaims(OA2State oa2State) {
            super(oa2State);
        }

        @Override
        public String getName() {
            return ID_TOKEN_CHECK_CLAIM_METHOD;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0};
        }

        @Override
        public void doMethod(String execPhase) throws Throwable {

        }

        @Override
        public QDLValue evaluate(QDLValue[] objects, State state) {
            // This is different than the others, so we have to do all of the steps for evaluation
            checkState(state);
            if (!isInit) {
                throw new IllegalStateException("You must call init first.");
            }
            try {
                getidTokenHandler().checkClaims();
            } catch (Throwable throwable) {
                return BooleanValue.False;
            }
            return BooleanValue.True;
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            if (argCount == 0) {
                doxx.add(getName() + "() - check if the current set of claims is valid. This also normalizes them (e.g. empty claims are removed.");
                doxx.add("Generally this is called right before the " + ID_TOKEN_FINISH_METHOD + " to see if something needs to be done.");
                doxx.add("This returns a true if the claims check and a false otherwise.");
                doxx.add("See also: " + ID_TOKEN_INIT_METHOD);
            }
            return doxx;
        }
    }

    @Override
    public JSONObject serializeToJSON() {
        return null;
    }

    @Override
    public void deserializeFromJSON(JSONObject jsonObject) {

    }
}
