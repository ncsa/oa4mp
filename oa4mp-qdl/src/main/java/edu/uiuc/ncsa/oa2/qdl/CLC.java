package edu.uiuc.ncsa.oa2.qdl;

import edu.uiuc.ncsa.myproxy.oauth2.tools.OA2CLCCommands;
import edu.uiuc.ncsa.myproxy.oauth2.tools.OA2CommandLineClient;
import edu.uiuc.ncsa.qdl.exceptions.QDLException;
import edu.uiuc.ncsa.qdl.extensions.QDLFunction;
import edu.uiuc.ncsa.qdl.extensions.QDLModuleMetaClass;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.variables.QDLNull;
import edu.uiuc.ncsa.qdl.variables.QDLStem;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import net.sf.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 7/22/21 at  10:41 AM
 */
public class CLC implements QDLModuleMetaClass {
    OA2CLCCommands clcCommands;

    boolean initCalled = false;

    protected void checkInit() {
        if ((clcCommands == null) || !initCalled) {
            throw new IllegalStateException("Error: You must call " + INIT_NAME + " before calling this function");
        }
    }

    protected QDLStem getTokens() {
        QDLStem result = new QDLStem();

        QDLStem at = new QDLStem();

        at.fromJSON(clcCommands.getDummyAsset().getAccessToken().toJSON());
        try {
            QDLStem jwt = new QDLStem();
            jwt.fromJSON(clcCommands.resolveFromToken(clcCommands.getDummyAsset().getAccessToken(), false));
            at.put("jwt", jwt);
        } catch (Throwable t) {

        }
        result.put("access_token", at);
        if (clcCommands.getDummyAsset().hasRefreshToken()) {
            QDLStem rt = new QDLStem();
            rt.fromJSON(clcCommands.getDummyAsset().getRefreshToken().toJSON());
            try {
                QDLStem jwt = new QDLStem();
                jwt.fromJSON(clcCommands.resolveFromToken(clcCommands.getDummyAsset().getRefreshToken(), false));
                rt.put("jwt", jwt);
            } catch (Throwable t) {

            }
            result.put("refresh_token", rt);
        }
        return result;
    }

    protected String DUMMY_ARG = "dummy"; // when creating input lines, need dummy arg for method name
    protected String INIT_NAME = "init";

    protected String checkInitMessage = "Be sure you have called the " + INIT_NAME + " function first or this will fail.";

    public class InitMethod implements QDLFunction {
        @Override
        public String getName() {
            return INIT_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{2};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            try {
                clcCommands = new OA2CLCCommands(false, state.getLogger(), new OA2CommandLineClient(state.getLogger()));
                clcCommands.load(new InputLine(DUMMY_ARG + " " + objects[1].toString() + "  " + objects[0].toString()));
                initCalled = true;
            } catch (Exception e) {
                state.getLogger().error("error initializing client", e);
                initCalled = false;
                clcCommands = null;
                if (DebugUtil.isEnabled()) {
                    e.printStackTrace();
                }
                return false;
            }
            return true;
        }


        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(file, name) - reads the configuration file and then loads the configuration with the given name. ");
            doxx.add("This sets the configuration and name.");
            doxx.add("This must be called before any other function.");
            return doxx;
        }
    }

    protected String CLAIMS_NAME = "claims";

    public class GetClaim implements QDLFunction {
        @Override
        public String getName() {
            return CLAIMS_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            QDLStem claims = new QDLStem();
            if (objects.length == 0) {
                try {
                    JSONObject jsonObject = clcCommands.getClaims();
                    claims.fromJSON(jsonObject);
                } catch (Exception e) {
                    throw new QDLException(getName() + " could not get the claims:'" + e.getMessage() + "'");

                }
            }
            return claims;
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "() - set the current set of user claims.");
          doxx.add("This is the same information as returned by the " + USER_INFO_NAME + " function.");
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    protected String GRANT_NAME = "grant";

    public class Grant implements QDLFunction {
        @Override
        public String getName() {
            return GRANT_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0, 1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            try {
                if (objects.length == 0) {

                    clcCommands.grant(new InputLine(DUMMY_ARG));
                }
                if (objects.length == 1) {
                    clcCommands.grant(new InputLine(DUMMY_ARG + " " + objects[0]));
                }
                QDLStem g = new QDLStem();

                g.fromJSON(clcCommands.getGrant().toJSON());
                return g;
            } catch (Exception e) {
                state.getLogger().error("error getting grant", e);
                if (DebugUtil.isEnabled()) {
                    e.printStackTrace();
                }
                return QDLNull.getInstance();
            }
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "([grant]) - set the current grant.");
            if (argCount == 0) {
                doxx.add(getName() + "() - set the grant from the clipboard");
            }
            if (argCount == 1) {
                doxx.add(getName() + "(grant) - set the grant");

            }
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    protected String ACCESS_NAME = "access";

    public class Access implements QDLFunction {
        @Override
        public String getName() {
            return ACCESS_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0, 1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            checkInit();
            String args = DUMMY_ARG;
            if (objects.length == 1) {
                if (objects[0] instanceof Boolean) {
                    if (!(Boolean) objects[0]) {
                        args = args + " " + clcCommands.NO_VERIFY_JWT;
                    }
                } else {
                    throw new IllegalArgumentException(getName() + " requires a boolean argument");
                }
            }
            try {
                clcCommands.access(new InputLine(args));
                return getTokens();
            } catch (Exception e) {
                state.getLogger().error("error getting access token", e);
                if (DebugUtil.isEnabled()) {
                    e.printStackTrace();
                }
            }
            return QDLNull.getInstance();
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "([verify_jwts]) get the access token.");
            doxx.add("verify_jwts - if true (default) verify any JWTs. If false, do not verify them.");
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    protected String URI_NAME = "uri";

    public class CreateURI implements QDLFunction {
        @Override
        public String getName() {
            return URI_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            checkInit();
            try {
                clcCommands.uri(new InputLine(DUMMY_ARG));
                return clcCommands.getCurrentURI().toString();
            } catch (Exception e) {
                if (DebugUtil.isEnabled()) {
                    e.printStackTrace();
                }
            }
            return QDLNull.getInstance();
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + " create the uri. This is returned and, if possible, copied to the clipboard.");
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    protected String REFRESH_NAME = "refresh";

    public class Refresh implements QDLFunction {
        @Override
        public String getName() {
            return REFRESH_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            checkInit();
            try {
                clcCommands.refresh(new InputLine(DUMMY_ARG));
                return getTokens();
            } catch (Exception e) {

                if (DebugUtil.isEnabled()) {
                    e.printStackTrace();
                }
            }
            return QDLNull.getInstance();
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + " refresh the tokens.");
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    protected String EXCHANGE_NAME = "exchange";

    public class Exchange implements QDLFunction {
        @Override
        public String getName() {
            return EXCHANGE_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            checkInit();
            try {
                clcCommands.exchange(new InputLine(DUMMY_ARG));
                return getTokens();
            } catch (Exception e) {
                if (DebugUtil.isEnabled()) {
                    e.printStackTrace();
                }
            }
            return QDLNull.getInstance();
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + " Do the token exchange.");
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    protected String REVOKE_NAME = "revoke";

    public class Revoke implements QDLFunction {
        @Override
        public String getName() {
            return REVOKE_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            checkInit();
            try {
                clcCommands.revoke(new InputLine(DUMMY_ARG));
                return Boolean.TRUE;
            } catch (Exception e) {

                if (DebugUtil.isEnabled()) {
                    e.printStackTrace();
                }
            }
            return Boolean.FALSE;
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            return null;
        }
    }

    protected String DEVICE_FLOW_NAME = "df";

    public class DeviceFlow implements QDLFunction {
        @Override
        public String getName() {
            return DEVICE_FLOW_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            checkInit();
            try {
                clcCommands.df(new InputLine(DUMMY_ARG));
                QDLStem QDLStem = new QDLStem();
                QDLStem.fromJSON(clcCommands.getDfResponse());
                return QDLStem;
            } catch (Exception e) {
                if (DebugUtil.isEnabled()) {
                    e.printStackTrace();
                }
            }
            return new QDLStem();
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + " initialte the device flow. If possible, the user code is copied to the clipboard.");
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    protected String INTROSPECT_NAME = "introspect";

    public class Introspect implements QDLFunction {
        @Override
        public String getName() {
            return INTROSPECT_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            checkInit();
            try {
                clcCommands.introspect(new InputLine(DUMMY_ARG));
                QDLStem QDLStem = new QDLStem();
                QDLStem.fromJSON(clcCommands.getIntrospectResponse());
                return QDLStem;
            } catch (Exception e) {

                if (DebugUtil.isEnabled()) {
                    e.printStackTrace();
                }
            }
            return new QDLStem();
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + " introspect on the current token.");
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    protected String USER_INFO_NAME = "user_info";

    public class UserInfo implements QDLFunction {
        @Override
        public String getName() {
            return USER_INFO_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            checkInit();
            QDLStem out = new QDLStem();
            try {
                clcCommands.user_info(new InputLine(DUMMY_ARG));
                out.fromJSON(clcCommands.getClaims());
            } catch (Exception e) {
                if (DebugUtil.isEnabled()) {
                    e.printStackTrace();
                }
            }
            return out;
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + " return the user info.");
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    protected String TOKENS_NAME = "tokens";

    public class Tokens implements QDLFunction {
        @Override
        public String getName() {
            return TOKENS_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            checkInit();
            return getTokens();
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + " initialte the device flow. If possible, the user code is copied to the clipboard.");
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    protected String WRITE_NAME = "write";

    public class Write implements QDLFunction {
        @Override
        public String getName() {
            return WRITE_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1, 2};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            String args = DUMMY_ARG + " " + objects[0];
            if (objects.length == 2) {
                args = args + " -m " + objects[1];
            }
            checkInit();
            try {
                clcCommands.write(new InputLine(args));
                return Boolean.TRUE;
            } catch (Exception e) {
                if (DebugUtil.isEnabled()) {
                    e.printStackTrace();
                }
            }
            return Boolean.FALSE;
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(file [,message]) - write the current state to the file");
            switch (argCount) {
                case 1:
                    doxx.add(getName() + "(file) writes to the file");
                    break;
                case 2:
                    doxx.add(getName() + "(file, message) write to the file and includes the given message");
                    break;
            }
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    protected String READ_NAME = "read";

    public class Read implements QDLFunction {
        @Override
        public String getName() {
            return READ_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            try {
                clcCommands.read(new InputLine(DUMMY_ARG + " " + objects[0]));
                return Boolean.TRUE;
            } catch (Exception e) {
                e.printStackTrace();
            }
            return Boolean.FALSE;
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(file) - read state previously saved by this client.");
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    protected String CLEAR_NAME = "clear";
    protected String LOAD_NAME = "load";
    protected String GET_PARAM = "get_param";

    public class GetParam implements QDLFunction {
        @Override
        public String getName() {
            return null;
        }

        @Override
        public int[] getArgCount() {
            return new int[0];
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            return null;
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            return null;
        }
    }

    protected String SET_PARAM = "set_param";
    protected String CLEAR_PARAMS = "clear_params";


}
