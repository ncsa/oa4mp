package edu.uiuc.ncsa.oa2.qdl;

import edu.uiuc.ncsa.myproxy.oauth2.tools.OA2CLCCommands;
import edu.uiuc.ncsa.myproxy.oauth2.tools.OA2CommandLineClient;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AccessToken;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.TokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.TokenUtils;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.OA2Claims;
import edu.uiuc.ncsa.qdl.exceptions.BadArgException;
import edu.uiuc.ncsa.qdl.exceptions.MissingArgException;
import edu.uiuc.ncsa.qdl.exceptions.QDLException;
import edu.uiuc.ncsa.qdl.extensions.QDLFunction;
import edu.uiuc.ncsa.qdl.extensions.QDLModuleMetaClass;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.variables.QDLList;
import edu.uiuc.ncsa.qdl.variables.QDLNull;
import edu.uiuc.ncsa.qdl.variables.QDLStem;
import edu.uiuc.ncsa.security.core.util.DateUtils;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.servlet.ServiceClientHTTPException;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import net.sf.json.JSONObject;

import java.util.*;

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
        result.put("access_token", tokenToStem(clcCommands.getDummyAsset().getAccessToken()));
        if (clcCommands.getDummyAsset().hasRefreshToken()) {
            result.put("refresh_token", tokenToStem(clcCommands.getDummyAsset().getRefreshToken()));
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
                clcCommands = new OA2CLCCommands(true, state.getLogger(), new OA2CommandLineClient(state.getLogger()));
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
            doxx.add("This sets the configuration and name and resets the state completely.");
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
            QDLStem g = new QDLStem();
            try {
                if (objects.length == 0) {

                    clcCommands.grant(new InputLine(DUMMY_ARG));
                }
                if (objects.length == 1) {
                    clcCommands.grant(new InputLine(DUMMY_ARG + " " + objects[0]));
                }

                g.fromJSON(clcCommands.getGrant().toJSON());
            } catch (Exception e) {
                state.getLogger().error("error getting grant", e);
                handleException(e);
            }
            return g;
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
            } catch (Exception e) {
                state.getLogger().error("error getting access token", e);
                handleException(e);
            }
            return getTokens();
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
            } catch (Exception e) {
                handleException(e);
            }
            return getTokens();
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
            ArrayList<String> args = new ArrayList<>();
            args.add("exchange");// name of function
            for(Object ooo : objects){
                if(ooo instanceof String){
                    args.add((String) ooo);
                }
            }
            String[] strings = new String[]{};
            strings = args.toArray(strings);
            try {
                clcCommands.exchange(new InputLine(strings));
            } catch (Exception e) {
                handleException(e);
            }
            return getTokens();
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "([-rt | [-at ]] [-x] Do the token exchange.");
            doxx.add("Arguments:");
            doxx.add("(None) = exchange the access token using the access token as the bearer token. Make sure it has not expired.");
            doxx.add("-at = same as no arguments");
            doxx.add("-rt = exchange refresh token, using the refresh token as the bearer token");
            doxx.add("-x = force using the refresh token as the bearer token");
            doxx.add("E.g.");
            doxx.add("exchange('-at', 'x');");
            doxx.add("would exchange the access token (possibly expired) using the (valid) refresh token.");
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    protected void handleException(Throwable t) throws QDLException {
        if (DebugUtil.isEnabled()) {
            t.printStackTrace();
        }
        if (t instanceof ServiceClientHTTPException) {
            ServiceClientHTTPException serviceClientHTTPException = (ServiceClientHTTPException) t;
            throw new QDLException(serviceClientHTTPException.getContent());
        }
        if (t instanceof QDLException) {
            throw (QDLException) t;
        }
        throw new QDLException(t.getMessage(), t);
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
            QDLStem QDLStem = new QDLStem();
            try {
                clcCommands.df(new InputLine(DUMMY_ARG));
                QDLStem.fromJSON(clcCommands.getDfResponse());
            } catch (Exception e) {
                handleException(e);
            }
            return QDLStem;
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
            QDLStem QDLStem = new QDLStem();
            try {
                clcCommands.introspect(new InputLine(DUMMY_ARG));
                QDLStem.fromJSON(clcCommands.getIntrospectResponse());
            } catch (Exception e) {
                handleException(e);
            }
            return QDLStem;
            //return new QDLStem();
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
                handleException(e);
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

    protected String CLEAR_NAME = "clear_param";

    public class ClearParam implements QDLFunction {
        @Override
        public String getName() {
            return CLEAR_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0, 1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            if (objects.length == 0) {
                try {
                    clcCommands.clear(new InputLine(), true);
                } catch (Exception e) {

                }
            }
            return Boolean.TRUE;
        }

        List<String> doxx = new ArrayList<>();

        @Override
        public List<String> getDocumentation(int argCount) {
            if (doxx.isEmpty()) {
                doxx.add(getName() + "() = clear all the state inluding any parameters. ");
                doxx.add("You can also recall " + INIT_NAME);
            }
            return doxx;
        }
    }

    protected String LOAD_NAME = "load";
    protected String GET_PARAM = "get_param";

    public class GetParam implements QDLFunction {
        @Override
        public String getName() {
            return GET_PARAM;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0, 1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            QDLStem stem = new QDLStem();
            QDLList qdlList = null;
            boolean isScalar = false;
            if (objects.length == 0) {
                qdlList = new QDLList();
                qdlList.appendAll(Arrays.asList(PARAM_FLAG_AUTHZ_SHORT, PARAM_FLAG_TOKEN, PARAM_FLAG_REFRESH, PARAM_FLAG_EXCHANGE));
            }
            if (objects.length == 1) {
                if (objects[0] instanceof String) {
                    isScalar = true;
                    qdlList = new QDLList();
                    qdlList.add(objects[0]);
                } else {
                    if (!(objects[0] instanceof QDLStem)) {
                        throw new BadArgException(getName() + " requires a stem or list as its argument", null);
                    }
                    qdlList = ((QDLStem) objects[0]).getQDLList();
                }
            }
            for (Object key : qdlList.values()) {
                HashMap<String, String> params = null;
                switch (key.toString()) {
                    case PARAM_FLAG_AUTHZ:
                    case PARAM_FLAG_AUTHZ_SHORT:
                        params = clcCommands.getRequestParameters();
                        break;
                    case PARAM_FLAG_TOKEN:
                    case PARAM_FLAG_TOKEN_SHORT:
                        params = clcCommands.getTokenParameters();
                        break;
                    case PARAM_FLAG_REFRESH:
                    case PARAM_FLAG_REFRESH_SHORT:
                        params = clcCommands.getRefreshParameters();
                        break;
                    case PARAM_FLAG_EXCHANGE:
                    case PARAM_FLAG_EXCHANGE_SHORT:
                        params = clcCommands.getExchangeParameters();
                        break;
                    default:
                        // do nothing.
                }
                if (params != null) {
                    QDLStem v = new QDLStem();
                    for (String key2 : params.keySet()) {
                        v.put(key2, params.get(key2));
                    }
                    if (isScalar) {
                        return v; // only one.
                    }
                    stem.put(key.toString(), v);
                }
            }
            return stem;
        }

        List<String> doxx = new ArrayList<>();

        @Override
        public List<String> getDocumentation(int argCount) {

            if (doxx.isEmpty()) {
                doxx.add(getName() + "([flag | flags.]) = return the parameters. If no argument, return all parameters as a stem");
                doxx.add("Otherwise, the flag or list of flags is");
                doxx.add(PARAM_FLAG_AUTHZ_SHORT + " | " + PARAM_FLAG_AUTHZ + " = authorization");
                doxx.add(PARAM_FLAG_TOKEN_SHORT + " | " + PARAM_FLAG_TOKEN + " = (access) token)");
                doxx.add(PARAM_FLAG_REFRESH_SHORT + " | " + PARAM_FLAG_REFRESH + " = refresh");
                doxx.add(PARAM_FLAG_EXCHANGE_SHORT + " | " + PARAM_FLAG_EXCHANGE + " = exchange");
                doxx.add("");
                doxx.add("");

                doxx.add("E.g.");
                doxx.add(getName() + "(" + PARAM_FLAG_AUTHZ + ")");
            }
            return doxx;
        }
    }

    protected String SET_PARAM = "set_param";
    protected String CLEAR_PARAMS = "clear_params";

    protected static final String PARAM_FLAG_AUTHZ = "authz";
    protected static final String PARAM_FLAG_AUTHZ_SHORT = "a";
    protected static final String PARAM_FLAG_TOKEN = "token";
    protected static final String PARAM_FLAG_TOKEN_SHORT = "t";

    protected static final String PARAM_FLAG_REFRESH = "refresh";
    protected static final String PARAM_FLAG_REFRESH_SHORT = "r";

    protected static final String PARAM_FLAG_EXCHANGE = "exchange";
    protected static final String PARAM_FLAG_EXCHANGE_SHORT = "e";

    public class SetParam implements QDLFunction {
        @Override
        public String getName() {
            return SET_PARAM;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            if (objects.length != 1) {
                throw new MissingArgException(getName() + " requires an argument", null);
            }
            if (!(objects[0] instanceof QDLStem)) {
                throw new BadArgException(getName() + " requires a stem as its argument", null);
            }
            QDLStem stem = (QDLStem) objects[0];
            for (Object key : stem.keySet()) {
                HashMap<String, String> params = null;
                switch (key.toString()) {
                    case PARAM_FLAG_AUTHZ:
                    case PARAM_FLAG_AUTHZ_SHORT:
                        params = clcCommands.getRequestParameters();
                        break;
                    case PARAM_FLAG_TOKEN:
                    case PARAM_FLAG_TOKEN_SHORT:
                        params = clcCommands.getTokenParameters();
                        break;
                    case PARAM_FLAG_REFRESH:
                    case PARAM_FLAG_REFRESH_SHORT:
                        params = clcCommands.getRefreshParameters();
                        break;
                    case PARAM_FLAG_EXCHANGE:
                    case PARAM_FLAG_EXCHANGE_SHORT:
                        params = clcCommands.getExchangeParameters();
                        break;
                    default:
                        // do nothing.
                }
                if (params != null) {
                    Object obj = stem.get(key);
                    if (obj instanceof QDLStem) {
                        QDLStem args = (QDLStem) obj;
                        for (Object keyArg : args.keySet()) {
                            if (keyArg instanceof String) {
                                params.put((String) keyArg, args.getString((String) keyArg));
                            }
                        }
                    }
                }
            }
            return Boolean.TRUE;
        }

        List<String> doc = new ArrayList<>();

        @Override
        public List<String> getDocumentation(int argCount) {
            if (doc.isEmpty()) {
                doc.add(getName() + "(arg.) - set the parameters for this client.");
                doc.add("keys are a | authz, e | exchange, t | token, r | refresh");
                doc.add(PARAM_FLAG_AUTHZ_SHORT + " | " + PARAM_FLAG_AUTHZ + " = authorization");
                doc.add(PARAM_FLAG_TOKEN_SHORT + " | " + PARAM_FLAG_TOKEN + " = (access) token)");
                doc.add(PARAM_FLAG_REFRESH_SHORT + " | " + PARAM_FLAG_REFRESH + " = refresh");
                doc.add(PARAM_FLAG_EXCHANGE_SHORT + " | " + PARAM_FLAG_EXCHANGE + " = exchange");
                doc.add("and each consists of a stem of key-value pairs");
                doc.add("E.g. set scope and code_challenge_method for the authz leg:");
                doc.add("param.'" + PARAM_FLAG_AUTHZ_SHORT + "' := {'scope':'read: write:','code_challenge_method':'256'};");
                doc.add(getName() + "(param.);");
                doc.add("You could also use '" + PARAM_FLAG_AUTHZ + "' for the key rather than '" + PARAM_FLAG_AUTHZ_SHORT + "'");
                doc.add("See also:" + GET_PARAM);
            }
            return doc;
        }
    }

    /**
     * This is rather similar to the {@link OA2CLCCommands#printToken(AccessToken, boolean, boolean)} and similar
     * commands, except rather than spitting it all out as print statements, the information about the token
     * is organized into a stem for further processing.
     *
     * @param token
     * @return
     */
    protected QDLStem tokenToStem(TokenImpl token) {
        QDLStem stem = new QDLStem();
        JSONObject json = clcCommands.resolveFromToken(token, false);
        stem.put("raw_token", token.getToken()); // always get this
        if (json == null) {
            // was not a JWT. No other way to tell except to try it.
            if (TokenUtils.isBase32(token.getToken())) {
                // Or we over-write the access token and lose base 64 encoding.
                TokenImpl accessToken2 = new TokenImpl(null);

                accessToken2.decodeToken(token.getToken());
                token = accessToken2;
                stem.put("decoded", token.getToken());
                //say("   decoded token:" + accessToken.getToken());
            }
            Date startDate = DateUtils.getDate(token.getToken());
            startDate.setTime(startDate.getTime() + token.getLifetime());
            Boolean isExpired = startDate.getTime() < System.currentTimeMillis();
            stem.put("expired", isExpired);
            if (!isExpired) {
                stem.put("lifetime", token.getLifetime());
                stem.put("ts", token.getIssuedAt());
                stem.put("expires", token.getIssuedAt() + token.getLifetime());
            }
        } else {
            // It is a JWT
            QDLStem jwt = new QDLStem();
            jwt.fromJSON(json);
            stem.put("jwt", jwt);
            Long expiration = -1L;
            Long timestamp = -1L;
            if (json.containsKey(OA2Claims.ISSUED_AT)) {
                timestamp = json.getLong(OA2Claims.ISSUED_AT) * 1000L;
                stem.put("ts", timestamp); // since its in sec., convert to ms.
            }
            if (json.containsKey(OA2Claims.EXPIRATION)) {
                expiration = json.getLong(OA2Claims.EXPIRATION) * 1000L;
                stem.put("expires", expiration);
                stem.put("lifetime", expiration - timestamp);
            }
            if (0 < expiration && 0 < timestamp) {
                if (System.currentTimeMillis() < expiration) {
                    stem.put("expired", Boolean.TRUE);
                } else {
                    stem.put("expired", Boolean.FALSE);
                }
            }
        }
        return stem;
    }

}
