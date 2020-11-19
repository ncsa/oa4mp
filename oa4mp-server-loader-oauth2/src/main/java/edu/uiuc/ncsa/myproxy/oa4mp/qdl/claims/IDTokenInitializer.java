package edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.AbstractPayloadConfig;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.IDTokenHandler;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.variables.StemVariable;
import net.sf.json.JSONObject;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/12/20 at  6:12 AM
 */
public class IDTokenInitializer implements Serializable {
    public static String ID_TOKEN_INIT_METHOD = "id_init";
    public static String ID_TOKEN_FINISH_METHOD = "id_finish";
    public static String ID_TOKEN_REFRESH_METHOD = "id_refresh";
    public static String ID_TOKEN_CHECK_CALIM_METHOD = "id_check_claim";

    IDTokenHandler idTokenHandler;

    protected IDTokenHandler getidTokenHandler() {
        return idTokenHandler;
    }

    boolean isInit = false;

    public abstract class IDMethods extends TokenHandlerMethod {

        @Override
        protected AbstractPayloadConfig getPayloadConfig() {
            return getClient().getIDTokenConfig();
        }

        public abstract void doMethod() throws Throwable;

        @Override
        public Object evaluate(Object[] objects, State state) {
            super.evaluate(objects, state);
            StemVariable idtoken = checkArg(objects, getName(), 0);
            StemVariable output = new StemVariable();
            if (idTokenHandler == null) {
                idTokenHandler = new IDTokenHandler(getPayloadHandlerConfig());
            }
            getidTokenHandler().setClaims((JSONObject) idtoken.toJSON());
            try {
                doMethod();
            } catch (Throwable throwable) {
                handleException(throwable);
            }

            output.fromJSON(getidTokenHandler().getClaims());
            return output;
        }

    }


    public class idInit extends IDMethods {
        @Override
        public String getName() {
            return ID_TOKEN_INIT_METHOD;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public void doMethod() throws Throwable {
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
        @Override
        public String getName() {
            return ID_TOKEN_FINISH_METHOD;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public void doMethod() throws Throwable {
            if (!isInit) {
                throw new IllegalStateException("Error: You must run init first.");
            }
            getidTokenHandler().finish();
        }


        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            if (argCount == 1) {
                doxx.add(getName() + "(id_token.) - finish any setup that is required for this token, e.g., the expiration time.");
                doxx.add("This is the last thing that you should invokde before returning the id token.");
                doxx.add("See also: " + ID_TOKEN_INIT_METHOD);
            }
            return doxx;
        }
    }

    public class idRefresh extends IDMethods {
        @Override
        public String getName() {
            return ID_TOKEN_REFRESH_METHOD;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public void doMethod() throws Throwable {
            if (!isInit) {
                throw new IllegalStateException("Error: You must run init first.");
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
        @Override
        public String getName() {
            return ID_TOKEN_CHECK_CALIM_METHOD;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0};
        }

        @Override
        public void doMethod() throws Throwable {

        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            // This is different than the others, so we have to do all of the steps for evaluation
            checkState(state);
            if (!isInit) {
                throw new IllegalStateException("You must call init first.");
            }
            try {
                getidTokenHandler().checkClaims();
            } catch (Throwable throwable) {
                return Boolean.FALSE;
            }
            return Boolean.TRUE;
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
}