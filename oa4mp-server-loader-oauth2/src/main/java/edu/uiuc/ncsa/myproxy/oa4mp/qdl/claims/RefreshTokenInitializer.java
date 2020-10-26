package edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.AbstractPayloadConfig;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens.BasicRefreshTokenHandler;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.variables.StemVariable;
import net.sf.json.JSONObject;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/12/20 at  6:16 AM
 */
public class RefreshTokenInitializer implements Serializable {
    public static String RT_INIT_METHOD = "rt_init";
    public static String RT_FINISH_METHOD = "rt_finish";
    public static String RT_REFRESH_METHOD = "rt_refresh";


    public abstract class RTMethod extends TokenHandlerMethod {
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
         protected abstract void doMethod() throws Throwable;

        @Override
        public Object evaluate(Object[] objects, State state) {
            super.evaluate(objects, state);
            StemVariable rt = checkArg(objects, getName(), 0);
            StemVariable output = new StemVariable();
            getRtHandler().setRTData((JSONObject) rt.toJSON());
            try {
                //getRtHandler().finish();
                doMethod();
            } catch (Throwable throwable) {
                handleException(throwable);
            }
            output.fromJSON(getRtHandler().getRTData());
            return output;
        }

    }


    public class rtInit extends RTMethod {
        @Override
        public String getName() {
            return RT_INIT_METHOD;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        protected void doMethod() throws Throwable {
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
        @Override
        public String getName() {
            return RT_FINISH_METHOD;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        protected void doMethod() throws Throwable {
            getRtHandler().finish();
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
        @Override
        public String getName() {
            return RT_REFRESH_METHOD;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        protected void doMethod() throws Throwable {
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
