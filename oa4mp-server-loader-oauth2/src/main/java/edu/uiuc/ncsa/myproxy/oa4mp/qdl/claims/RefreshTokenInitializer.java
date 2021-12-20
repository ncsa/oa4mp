package edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.AbstractPayloadConfig;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens.BasicRefreshTokenHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting.OA2State;
import edu.uiuc.ncsa.qdl.extensions.QDLModuleMetaClass;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.variables.StemVariable;
import net.sf.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

import static edu.uiuc.ncsa.security.oauth_2_0.jwt.ScriptingConstants.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/12/20 at  6:16 AM
 */
public class RefreshTokenInitializer implements QDLModuleMetaClass {
    public static String RT_INIT_METHOD     = "rt_init";
    public static String RT_FINISH_METHOD = "rt_finish";
    public static String RT_REFRESH_METHOD = "rt_refresh";

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

    }

    public abstract class RTMethod extends TokenHandlerMethod {
        public RTMethod(OA2State oa2State) {
            super(oa2State);
        }

        @Override
        protected AbstractPayloadConfig getPayloadConfig() {
            return getClient().getRefreshTokensConfig();
        }

        BasicRefreshTokenHandler rtHandler;

        public BasicRefreshTokenHandler getRtHandler() {
            if (rtHandler == null) {
                rtHandler = new BasicRefreshTokenHandler(getPayloadHandlerConfig());
            }
            return rtHandler;
        }

        protected abstract void doMethod(String execPhase) throws Throwable;

        @Override
        public Object evaluate(Object[] objects, State state) {
            super.evaluate(objects, state);
            StemVariable rt = checkArg(objects, getName(), 0);
            StemVariable output = new StemVariable();
            getRtHandler().setRTData((JSONObject) rt.toJSON());
            String execPhase = null;
            if (1 < objects.length) {
                if (!(objects[1] instanceof String)) {
                    throw new IllegalArgumentException("Error: The second argument must be a string.");
                }
                execPhase = (String) objects[1];
            }
            try {
                //getRtHandler().finish();
                doMethod(execPhase);
            } catch (Throwable throwable) {
                handleException(throwable);
            }
            output.fromJSON(getRtHandler().getRTData());
            return output;
        }

    }


    public class rtInit extends RTMethod {
        public rtInit(OA2State oa2State) {
            super(oa2State);
        }

        @Override
        public String getName() {
            return RT_INIT_METHOD;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        protected void doMethod(String execPhase) throws Throwable {
            getRtHandler().init();
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            if (argCount == 1) {
                doxx.add(getName() + "(refresh_token.) - intialize a refresh token.");
                doxx.add("");
                doxx.add("See also: " + RT_FINISH_METHOD + ", " + RT_REFRESH_METHOD);
            }
            return doxx;
        }
    }

    public class rtFinish extends RTMethod {
        public rtFinish(OA2State oa2State) {
            super(oa2State);
        }

        @Override
        public String getName() {
            return RT_FINISH_METHOD;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        protected void doMethod(String execPhase) throws Throwable {
            getRtHandler().finish(execPhase);
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            if (argCount == 1) {
                doxx.add(getName() + "(refresh_token.) - finish the initialization for this refresh token.");
                doxx.add("See also: " + RT_INIT_METHOD + ", " + RT_REFRESH_METHOD);
            }
            return doxx;
        }
    }

    public class rtRefresh extends RTMethod {
        public rtRefresh(OA2State oa2State) {
            super(oa2State);
        }

        @Override
        public String getName() {
            return RT_REFRESH_METHOD;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        protected void doMethod(String execPhase) throws Throwable {
            getRtHandler().refresh();
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            if (argCount == 1) {
                doxx.add(getName() + "(refresh_token.) - do any required tasks to make a token for the refresh phase.");
                doxx.add("See also: " + RT_INIT_METHOD + ", " + RT_FINISH_METHOD);
            }
            return doxx;
        }
    }
}
