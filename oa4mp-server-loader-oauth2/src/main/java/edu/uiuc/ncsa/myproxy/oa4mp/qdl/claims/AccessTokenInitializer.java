package edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.AbstractAccessTokenHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.AbstractPayloadConfig;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens.*;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting.OA2State;
import edu.uiuc.ncsa.qdl.extensions.QDLModuleMetaClass;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.variables.QDLStem;
import edu.uiuc.ncsa.security.oauth_2_0.server.RFC9068Constants;
import net.sf.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/9/20 at  9:40 AM
 */
public class AccessTokenInitializer implements QDLModuleMetaClass {
    public static String AT_INIT_METHOD = "at_init";
    public static String AT_FINISH_METHOD = "at_finish";
    public static String AT_REFRESH_METHOD = "at_refresh";

    public AbstractAccessTokenHandler getAtHandler() {
        return atHandler;
    }

    AbstractAccessTokenHandler atHandler;

    /**
     * Super class to collect common methods and tasks.
     */
    public abstract class ATMethod extends TokenHandlerMethod {
        public ATMethod(OA2State oa2State) {
            super(oa2State);
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            super.evaluate(objects, state);
            // init(type, access_token.);

            QDLStem at = checkArg(objects, getName(), 1);
            setupHandler(objects);
            JSONObject j = (JSONObject) at.toJSON();
            getAtHandler().setAtData(new JSONObject()); // handler won't set accounting info unless this is empty.
            try {
                doMethod();
            } catch (Throwable throwable) {
                handleException(throwable);
            }
            QDLStem newAT = new QDLStem();
            JSONObject newToken = getAtHandler().getAtData();
            newToken.putAll(j);
            getAtHandler().setAtData(newToken);
            newAT.fromJSON(newToken);
            return newAT;
        }

        protected void setupHandler(Object[] objects) {
            if (!(objects[0] instanceof String)) {
                throw new IllegalArgumentException("Error: You must supply the type of the token.");
            }
            String type = (String) objects[0];
            switch (type) {
                case WLCGConstants.WLCG_TAG:
                    atHandler = new WLCGTokenHandler(getPayloadHandlerConfig());
                    break;
                case SciTokenConstants.SCI_TOKEN_TAG:
                case SciTokenConstants.SCI_TOKEN_TAG2:
                    atHandler = new ScitokenHandler(getPayloadHandlerConfig());
                    break;
                case RFC9068Constants.RFC9068_TAG:
                case RFC9068Constants.RFC9068_TAG2:
                    atHandler = new RFC9068ATHandler(getPayloadHandlerConfig());
                    break;
                case AbstractAccessTokenHandler.AT_DEFAULT_HANDLER_TYPE:
                    atHandler = new AbstractAccessTokenHandler(getPayloadHandlerConfig());
                default:
                    throw new IllegalArgumentException("Unknown token type.");
            }
        }

        /**
         * The method this class wraps.
         *
         * @throws Throwable
         */
        protected abstract void doMethod() throws Throwable;

        @Override
        protected AbstractPayloadConfig getPayloadConfig() {
            return getClient().getAccessTokensConfig();
        }

        protected void addTypeDoc(List<String> doxx) {
            doxx.add("type - one of '" + WLCGConstants.WLCG_TAG + " or " + SciTokenConstants.SCI_TOKEN_TAG + " that determines the type of token.");
        }
    }

    public class atInit extends ATMethod {
        public atInit(OA2State oa2State) {
            super(oa2State);
        }

        @Override
        public String getName() {
            return AT_INIT_METHOD;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{2};
        }

        @Override
        protected void doMethod() throws Throwable {
            getAtHandler().init();
            isInit = true;
        }


        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            if (argCount == 2) {
                doxx.add(getName() + "(type, access_token.) - initialize an access token.");
                addTypeDoc(doxx);
                doxx.add("Every access token type has a specific set of required claims that it must contain.");
                doxx.add("the second argument is a stem of claims of whatever you want. This adds the accounting information to that stem, ");
                doxx.add("and returns a new stem of the result.");
                doxx.add("See also: " + AT_FINISH_METHOD);
            }
            return doxx;
        }
    }

    public class atRefresh extends ATMethod {
        public atRefresh(OA2State oa2State) {
            super(oa2State);
        }

        @Override
        protected void doMethod() throws Throwable {
            getAtHandler().refresh();

        }

        @Override
        public String getName() {
            return AT_REFRESH_METHOD;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{2};
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            if (argCount == 2) {
                doxx.add(getName() + "(type, access_token.) - refresh the access token with any specific information it requires.");
                addTypeDoc(doxx);
                doxx.add("You would call this in refresh phase.");
                doxx.add("See also: " + AT_INIT_METHOD + ", " + AT_FINISH_METHOD);
            }
            return doxx;
        }
    }

    public class atFinish extends ATMethod {
        public atFinish(OA2State oa2State) {
            super(oa2State);
        }

        @Override
        public String getName() {
            return AT_FINISH_METHOD;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{2, 3};
        }

        @Override
        protected void doMethod() throws Throwable {
            // no-op.
        }

        /*
        Keep this! It is very different from the standard for these methods since there is a flag for evaluating templates.
         */
        @Override
        public Object evaluate(Object[] objects, State state) {
            if (objects.length != getArgCount()[0] && objects.length != getArgCount()[1]) {
                throw new IllegalArgumentException("Error:" + getName() + " requires 2 or 3  arguments and you supplied " + objects.length);
            }
            oa2State = checkState(state);
            setupHandler(objects);

            QDLStem at = checkArg(objects, getName(), 1);
            QDLStem output = new QDLStem();
            Boolean doTemplates = Boolean.TRUE;
            Boolean isQuery = Boolean.FALSE;
            if (objects.length == 3) {
                if ((objects[2] instanceof Boolean)) {
                    doTemplates = (Boolean) objects[2];
                } else {
                    throw new IllegalArgumentException("Error: the third argument must be a boolean");
                }
            }
            if (objects.length == 4) {
                if ((objects[3] instanceof Boolean)) {
                    isQuery = (Boolean) objects[3];
                } else {
                    throw new IllegalArgumentException("Error: the fourth argument must be a boolean");
                }
            }

            getAtHandler().setAtData((JSONObject) at.toJSON());
            try {
                getAtHandler().finish(doTemplates, isQuery);
            } catch (Throwable throwable) {
                handleException(throwable);
            }

            output.fromJSON(getAtHandler().getAtData());
            return output;
        }


        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            switch (argCount) {
                case 2:
                    doxx.add(getName() + "(type,  access_token.) - finish the creation of the token. ");
                    break;
                case 3:
                    doxx.add(getName() + "(type,  access_token., do_templates) - finish the creation of the token. ");
                    break;
                case 4:
                    doxx.add(getName() + "(type,  access_token., do_templates, is_query) - finish the creation of the token.");
                    doxx.add("is_query - treat the request as a query for available scopes. Default is false.");
                    break;
                default:
                    return doxx;
            }
            addTypeDoc(doxx);
            doxx.add("access_token. - the stem that contains the claims for this token.");
            // need to put this in the right place in the documentation.
            if (argCount == 3) {
                doxx.add("doTemplates - if there are templates in the configuration, run those if this is true.");
            }
            doxx.add("See also: " + AT_INIT_METHOD);

            return doxx;
        }
    }

}
