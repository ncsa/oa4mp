package edu.uiuc.ncsa.oa2.qdl;

import edu.uiuc.ncsa.myproxy.oauth2.tools.OA2CLCCommands;
import edu.uiuc.ncsa.myproxy.oauth2.tools.OA2CommandLineClient;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AccessToken;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.RefreshTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.TokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.TokenUtils;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.OA2Claims;
import edu.uiuc.ncsa.qdl.exceptions.BadArgException;
import edu.uiuc.ncsa.qdl.exceptions.MissingArgException;
import edu.uiuc.ncsa.qdl.extensions.QDLFunction;
import edu.uiuc.ncsa.qdl.extensions.QDLModuleMetaClass;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.variables.QDLList;
import edu.uiuc.ncsa.qdl.variables.QDLStem;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.DateUtils;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import net.sf.json.JSONObject;

import java.net.URI;
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
        public Object evaluate(Object[] objects, State state) throws Throwable {
            try {
                DebugUtil.setEnabled(true);
                clcCommands = new OA2CLCCommands(true, state.getLogger(), new OA2CommandLineClient(state.getLogger()));
                // note that the order of the arguments swaps.
                clcCommands.load(new InputLine(DUMMY_ARG + " " + objects[1].toString() + "  " + objects[0].toString()));
                initCalled = true;
            } catch (Throwable e) {
                state.getLogger().error("error initializing client", e);
                initCalled = false;
                clcCommands = null;
                if (DebugUtil.isEnabled()) {
                    e.printStackTrace();
                }
                throw e;
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
        public Object evaluate(Object[] objects, State state) throws Throwable{
            QDLStem claims = new QDLStem();
            if (objects.length == 0) {
//                try {
                    JSONObject jsonObject = clcCommands.getClaims();
                    claims.fromJSON(jsonObject);
  /*              } catch (Exception e) {
                    throw new GeneralException(getName() + " could not get the claims:'" + e.getMessage() + "'");

                }
  */          }
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
        public Object evaluate(Object[] objects, State state) throws Throwable{
            QDLStem g = new QDLStem();
                clcCommands.grant(argsToInputLine(getName(), objects));
            if(clcCommands.getGrant() == null){
                throw new GeneralException("unable to get grant");
            }
            g.fromJSON(clcCommands.getGrant().toJSON());
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
        public Object evaluate(Object[] objects, State state) throws Throwable {
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
                clcCommands.access(new InputLine(args));

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

    protected String GET_CERT_NAME = "get_cert";
    public class GetCert implements QDLFunction{
        @Override
        public String getName() {
            return GET_CERT_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0};
        }

        @Override
        public Object evaluate(Object[] objects, State state) throws Throwable {
            clcCommands.get_cert(argsToInputLine(getName(), objects));
            if(clcCommands.hasX509Certificates()){
                return clcCommands.getX509CertificateString();
            }
            return "";
        }

        List<String> dd = new ArrayList<>();

        @Override
        public List<String> getDocumentation(int argCount) {
            if(dd.isEmpty()){
                 dd.add(getName() + "() - get a certificate (chain).");
                 dd.add("Note that the client must be configured with the correct getcert scope and the");
                 dd.add("server must support MyProxy.");
            }
            return dd;
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
        public Object evaluate(Object[] objects, State state) throws Throwable{
            checkInit();
                clcCommands.uri(argsToInputLine(getName(), objects));
                return clcCommands.getCurrentURI().toString();
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
        public Object evaluate(Object[] objects, State state) throws Throwable{
            checkInit();
          //  try {
                clcCommands.refresh(argsToInputLine(getName(), objects));
           /* } catch (Exception e) {
                handleException(e);
            }*/
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
            return new int[]{0, 1, 2};
        }

        @Override
        public Object evaluate(Object[] objects, State state) throws Throwable {
            checkInit();
            clcCommands.exchange(argsToInputLine(getName(), objects));
            return getTokens();
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "([-rt | [-at ]] [-x] Do the token exchange.");
            doxx.add("returns: Both tokens, but the requested token is updated.");
            doxx.add("Arguments:");
            doxx.add("(None) = exchange the access token using the access token as the bearer token. Make sure it has not expired.");
            doxx.add("-at = same as no arguments");
            doxx.add("-rt = exchange refresh token, using the refresh token as the bearer token");
            doxx.add("-x = force using the refresh token as the bearer token");
            doxx.add("E.g.");
            doxx.add("exchange('-at', 'x');");
            doxx.add("would exchange the access token (possibly expired) using the (valid) refresh token.");
            doxx.add("The result contains both access_token and refresh_token, but note that only the access token");
            doxx.add("has changed.");
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    /**
     * Convert an array of strings (passed to the function) into an {@link InputLine} to be
     * consumed by the CLC.
     *
     * @param name
     * @param objects
     * @return
     */
    protected InputLine argsToInputLine(String name, Object[] objects) {
        ArrayList<String> args = new ArrayList<>();
        args.add(name);// name of function
        for (Object ooo : objects) {
            if (ooo instanceof String) {
                args.add((String) ooo);
            }
        }
        String[] strings = new String[]{};
        strings = args.toArray(strings);
        return new InputLine(strings);
    }

    protected void handleException(Throwable t)  {
        if (DebugUtil.isEnabled()) {
            t.printStackTrace();
        }
         if(t instanceof RuntimeException){
             throw (RuntimeException)t;
         }
        throw new GeneralException(t.getMessage(), t);
    }

    protected String REVOKE_NAME = "revoke";

    public class Revoke implements QDLFunction {
        @Override
        public String getName() {
            return REVOKE_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0, 1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) throws Throwable{
            checkInit();
//            try {
                clcCommands.revoke(argsToInputLine(getName(), objects));
                return Boolean.TRUE;
  /*          } catch (Exception e) {

                if (DebugUtil.isEnabled()) {
                    e.printStackTrace();
                }
            }
            return Boolean.FALSE;
  */      }

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
        public Object evaluate(Object[] objects, State state) throws Throwable {
            checkInit();
            QDLStem QDLStem = new QDLStem();
            clcCommands.df(argsToInputLine(getName(), objects));
            QDLStem.fromJSON(clcCommands.getDfResponse());
            return QDLStem;
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + " initiate the device flow. If possible, the user code is copied to the clipboard.");
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
            return new int[]{0, 1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) throws Throwable {
            checkInit();
            QDLStem QDLStem = new QDLStem();
            clcCommands.introspect(argsToInputLine(getName(), objects));
            QDLStem.fromJSON(clcCommands.getIntrospectResponse());
            return QDLStem;
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
        public Object evaluate(Object[] objects, State state) throws Throwable {
            checkInit();
            QDLStem out = new QDLStem();
            clcCommands.user_info(argsToInputLine(getName(), objects));
            out.fromJSON(clcCommands.getClaims());
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
        public Object evaluate(Object[] objects, State state) throws Throwable {
            String args = DUMMY_ARG + " " + objects[0];
            if (objects.length == 2) {
                args = args + " -m " + objects[1];
            }
            checkInit();
            clcCommands.write(new InputLine(args));
            return Boolean.TRUE;
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
            return new int[]{1, 2};
        }

        @Override
        public Object evaluate(Object[] objects, State state) throws Throwable {
            clcCommands = new OA2CLCCommands(true, state.getLogger(), new OA2CommandLineClient(state.getLogger()));
            clcCommands.read(argsToInputLine(getName(), objects));
            initCalled = true;
            return Boolean.TRUE;
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(file) - read state previously saved by this client.");
            doxx.add(getName() + "(file, '-p') - provision current client from this saved state (used by ersatz clients).");
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
        public Object evaluate(Object[] objects, State state) throws Throwable {
            if (objects.length == 0) {
                clcCommands.clear(new InputLine(), true);
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
                stem.put("jti", token.getToken());
                //say("   decoded token:" + accessToken.getToken());
            }
            Date expirationDate = DateUtils.getDate(token.getToken());
            expirationDate.setTime(expirationDate.getTime() + token.getLifetime());
            Boolean isExpired = expirationDate.getTime() < System.currentTimeMillis();
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
            stem.put("jti", jwt.getString("jti"));
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
                    stem.put("expired", Boolean.FALSE);
                } else {
                    stem.put("expired", Boolean.TRUE);
                }
            }
        }
        return stem;
    }

    /*
          Typical OA4MP access token
     expired : false
     expires : 1675711991120
         jti : https://localhost:9443/oauth2/352fca7395ff11ecbf2e7e1b1c6b5feb?type=accessToken&ts=1675711091120&version=v2.0&lifetime=900000
    lifetime : 900000
   raw_token : NB2HI4DTHIXS63DPMNQWY2DPON2DUOJUGQZS633BOV2GQMRPGM2TEZTDME3TGOJVMZTDCMLFMNRGMMTFG5STCYRRMM3GENLGMVRD65DZOBST2YLDMNSXG42UN5VWK3RGORZT2MJWG42TOMJRGA4TCMJSGATHMZLSONUW63R5OYZC4MBGNRUWMZLUNFWWKPJZGAYDAMBQ
          ts : 1675711091120

       Typical OA4MP JWT
     expired : false
     expires : 1675711409000
         jti : https://localhost:9443/oauth2/6a677121d5745b0c21df43b1e50ddabf?type=accessToken&ts=1675711115672&version=v2.0&lifetime=300000
         jwt :   aud : https://localhost/fermilab
                 exp : 1675711409, iat:1675711109
                 iss : https://localhost:9443/oauth2
                 jti : https://localhost:9443/oauth2/6a677121d5745b0c21df43b1e50ddabf?type=accessToken&ts=1675711115672&version=v2.0&lifetime=300000
                 nbf : 1675711104
               scope : read:/home/http://cilogon.org/serverT/users/21340363 write:/data/http://cilogon.org/serverT/users/21340363/cluster/node47 x.y:/abc/def/pqr
                 sub : http://cilogon.org/serverT/users/21340363,
                 ver : scitoken:2.0}
    lifetime : 300000
   raw_token : eyJ0eXAiOiJKV1QiLCJraWQiOiJFQzlGQ0ZDQjM3MTZBQzRDMjI3OURGNDJFQzk4Q0FCRiIsImFsZyI6IlJTMjU2In0.eyJpc3MiOiJodHRwczovL2xvY2FsaG9zdDo5NDQzL29hdXRoMiIsImF1ZCI6Imh0dHBzOi8vbG9jYWxob3N0L2Zlcm1pbGFiIiwiZXhwIjoxNjc1NzExNDA5LCJuYmYiOjE2NzU3MTExMDQsImlhdCI6MTY3NTcxMTEwOSwic3ViIjoiaHR0cDovL2NpbG9nb24ub3JnL3NlcnZlclQvdXNlcnMvMjEzNDAzNjMiLCJ2ZXIiOiJzY2l0b2tlbjoyLjAiLCJqdGkiOiJodHRwczovL2xvY2FsaG9zdDo5NDQzL29hdXRoMi82YTY3NzEyMWQ1NzQ1YjBjMjFkZjQzYjFlNTBkZGFiZj90eXBlPWFjY2Vzc1Rva2VuJnRzPTE2NzU3MTExMTU2NzImdmVyc2lvbj12Mi4wJmxpZmV0aW1lPTMwMDAwMCIsInNjb3BlIjoicmVhZDovaG9tZS9odHRwOi8vY2lsb2dvbi5vcmcvc2VydmVyVC91c2Vycy8yMTM0MDM2MyB3cml0ZTovZGF0YS9odHRwOi8vY2lsb2dvbi5vcmcvc2VydmVyVC91c2Vycy8yMTM0MDM2My9jbHVzdGVyL25vZGU0NyB4Lnk6L2FiYy9kZWYvcHFyIn0.TjSe9rIifXk0LLF7lPfJNxbSm9kcEXjT9Rk4ULBd-9AFP72rjdM_gqrBW-FXDD7ta0wKbU7XByhuQanA_cPdPkfXpZPx4PbRR9fNENXM2pMFHSIJbawh64setnThC0eLoNCgbEzAYxEibkoA7PtD8pvvjz-7sh8PUuKrHFt3OSOSrK7IY05PN8ZdlRJN1zYaM7XO7p1GnXCgB_Q21jKl5XgzrnFAq0-2vUcGlPhQI4aUBqDyw6CJV2esiqcxs9RTmJ4D60F1cC1EewGry9jGJmuvA1Sbn5ZRNnjSAdP8QJcCnMMeJW1gLlfa-ZIc2N9MkjX9Sun4jPqGsl0FSh8PWA
          ts : 1675711109000
     */
    protected AccessTokenImpl stemToAT(QDLStem stem) {
        if(stem.containsKey("jwt")){
                    return new AccessTokenImpl(stem.getString("raw_token"), URI.create(stem.getString("jti")));
                }
                 return new AccessTokenImpl(stem.getString("raw_token"), URI.create(stem.getString("jti")));
    }

    /*
          Typical OA4MP refresh token
     expired : false
     expires : 1675712091120
         jti : https://localhost:9443/oauth2/149dfd710908158d4b32ac430dd7c3df?type=refreshToken&ts=1675711091120&version=v2.0&lifetime=1000000
    lifetime : 1000000
   raw_token : NB2HI4DTHIXS63DPMNQWY2DPON2DUOJUGQZS633BOV2GQMRPGE2DSZDGMQ3TCMBZGA4DCNJYMQ2GEMZSMFRTIMZQMRSDOYZTMRTD65DZOBST24TFMZZGK43IKRXWWZLOEZ2HGPJRGY3TKNZRGEYDSMJRGIYCM5TFOJZWS33OHV3DELRQEZWGSZTFORUW2ZJ5GEYDAMBQGAYA
          ts : 1675711091120


     Typical JWT refresh token
     expired : false
     expires : 1675712009000
         jti : https://localhost:9443/oauth2/1ebc84fb89e63ab6c4a39bd827af16c3?type=refreshToken&ts=1675711115672&version=v2.0&lifetime=900000
         jwt : {aud:https://localhost/test, exp:1675712009, iat:1675711109, jti:https://localhost:9443/oauth2/1ebc84fb89e63ab6c4a39bd827af16c3?type=refreshToken&ts=1675711115672&version=v2.0&lifetime=900000, nbf:1675711104}
    lifetime : 900000
   raw_token : eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdWQiOiJodHRwczovL2xvY2FsaG9zdC90ZXN0IiwiZXhwIjoxNjc1NzEyMDA5LCJuYmYiOjE2NzU3MTExMDQsImlhdCI6MTY3NTcxMTEwOSwianRpIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6OTQ0My9vYXV0aDIvMWViYzg0ZmI4OWU2M2FiNmM0YTM5YmQ4MjdhZjE2YzM_dHlwZT1yZWZyZXNoVG9rZW4mdHM9MTY3NTcxMTExNTY3MiZ2ZXJzaW9uPXYyLjAmbGlmZXRpbWU9OTAwMDAwIn0.
          ts : 1675711109000
     */
    protected RefreshTokenImpl stemToRT(QDLStem stem) {
        if(stem.containsKey("jwt")){
            return new RefreshTokenImpl(stem.getString("raw_token"), URI.create(stem.getString("jti")));
        }
         return new RefreshTokenImpl(stem.getString("raw_token"), URI.create(stem.getString("jti")));
    }

    public static String ACCESS_TOKEN_ACCESSOR = "at";
    public static String REFRESH_TOKEN_ACCESSOR = "rt";

    public class AccessAT implements QDLFunction {
        @Override
        public String getName() {
            return ACCESS_TOKEN_ACCESSOR;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0, 1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            if (1 < objects.length) {
                throw new IllegalArgumentException(getName() + " takes at most one argument.");
            }
            if (objects.length == 0) {
                return tokenToStem(clcCommands.getDummyAsset().getAccessToken());
            }
            if (!(objects[0] instanceof QDLStem)) {
                throw new IllegalArgumentException("The argument to " + getName() + " must be a stem.");
            }
            QDLStem newAT = (QDLStem) objects[0];
            QDLStem oldAT = tokenToStem(clcCommands.getDummyAsset().getAccessToken());
            clcCommands.getDummyAsset().setAccessToken(stemToAT(newAT));
            return oldAT;
        }

        List<String> dd = null;

        @Override
        public List<String> getDocumentation(int argCount) {
            if (dd == null) {
                dd = new ArrayList<>();
                dd.add(getName() + "({new_access_token.}) - get or set the current access token");
                dd.add("If no argument, return the current token or null of none.");
                dd.add("Otherwise, the argument is the new access token, which is used hencforth. ");
                dd.add("if you set the token, the previous one is returned.");
            }
            return dd;
        }
    }

    public class AccessRT implements QDLFunction {
        @Override
        public String getName() {
            return REFRESH_TOKEN_ACCESSOR;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0, 1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            if (1 < objects.length) {
                throw new IllegalArgumentException(getName() + " takes at most one argument.");
            }
            if (objects.length == 0) {
                return tokenToStem(clcCommands.getDummyAsset().getRefreshToken());
            }
            if (!(objects[0] instanceof QDLStem)) {
                throw new IllegalArgumentException("The argument to " + getName() + " must be a stem.");
            }
            QDLStem newRT = (QDLStem) objects[0];
            QDLStem oldRT = tokenToStem(clcCommands.getDummyAsset().getRefreshToken());
            clcCommands.getDummyAsset().setRefreshToken(stemToRT(newRT));
            return oldRT;
        }

        List<String> dd = null;

        @Override
        public List<String> getDocumentation(int argCount) {
            if (dd == null) {
                dd = new ArrayList<>();
                dd.add(getName() + "({new_refresh_token.}) - get or set the current refresh token");
                dd.add("If no argument, return the current token or null of none.");
                dd.add("Otherwise, the argument is the new refresh token, which is used hencforth. ");
                dd.add("if you set the token, the previous one is returned.");

            }
            return dd;
        }
    }
    public static String RFC7523_NAME = "rfc7523";
    public class RFC7523 implements QDLFunction{
        @Override
        public String getName() {
            return RFC7523_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0, 1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) throws Throwable {
            checkInit();
            Map parameters = new HashMap();
            if(objects.length == 1){
                if(objects[0] instanceof String){
                    parameters.put(OA2Claims.SUBJECT, objects[0]);
                }else{
                    if(objects[0] instanceof QDLStem){
                        QDLStem stem = (QDLStem) objects[0];
                          for(Object key : stem.keySet()){
                              Object value = stem.get(key);
                              parameters.put(key, value);
                          }
                    }else{
                        throw new IllegalArgumentException("unknown argument type for " + getName());
                    }
                }
            }
                clcCommands.rfc7523(parameters);

            return getTokens();        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> dd = new ArrayList<>();
            switch (argCount){
                case 0:
                    dd.add(getName() + "() - issue grant request using default, 'username' is the client ID");
                    dd.add("E.g.");
                    dd.add(getName()+"()");
                    dd.add("Sends a basic request with no additional parameters. Returns the tokens and claims");
                    break;
                case 1:
                    dd.add(getName()+"(username | arg.) - issue grant request using the username or the entries of arg.");
                    dd.add("   The keys and values of arg. are sent as parameters, so be sure that values are strings.");
                    dd.add("\nE.g. with parameters");
                    dd.add(getName() + "('igwn-robot@bigstate.edu')");
                    dd.add("Sends request with the user name (as the subject of the request token). This is used on the");
                    dd.add("service as if the user logged in with the given name, so all e.g. QDL scripts will run against that name.");
                    dd.add("\nE.g.");
                    dd.add(getName() + "('sub':'bob@bigstate.edu','lifetime':1000000)");
                    dd.add("sends the request with the given user name and the parameter (in this case, requesting a certificate lifetime).");
                    break;
            }

            return dd;
        }
    }
}
