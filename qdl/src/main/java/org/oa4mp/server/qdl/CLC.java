package org.oa4mp.server.qdl;

import edu.uiuc.ncsa.security.core.util.StringUtils;
import org.oa4mp.server.admin.myproxy.oauth2.tools.OA2CLCCommands;
import org.oa4mp.server.admin.myproxy.oauth2.tools.OA2CommandLineClient;
import org.oa4mp.server.qdl.clc.QDLCLC;
import org.oa4mp.delegation.server.server.claims.OA2Claims;
import org.oa4mp.client.loader.OA2ClientEnvironment;
import org.oa4mp.delegation.common.token.impl.*;
import org.qdl_lang.exceptions.BadArgException;
import org.qdl_lang.exceptions.MissingArgException;
import org.qdl_lang.extensions.QDLFunction;
import org.qdl_lang.extensions.QDLMetaModule;
import org.qdl_lang.state.State;
import org.qdl_lang.variables.QDLList;
import org.qdl_lang.variables.QDLNull;
import org.qdl_lang.variables.QDLStem;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.DateUtils;
import edu.uiuc.ncsa.security.core.util.DebugConstants;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.servlet.ServiceClient;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.net.URI;
import java.util.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 7/22/21 at  10:41 AM
 */
public class CLC implements QDLMetaModule {
    OA2CLCCommands clcCommands;

    boolean initCalled = false;

    protected void checkInit() {
        if ((clcCommands == null) || !initCalled) {
            throw new IllegalStateException("you must call " + INIT_NAME + " before calling this function");
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

    /**
     * For a stem with the keys access_token and refresh-token, set the current token
     *
     * @param newTokens
     * @return
     */
    protected void setTokens(QDLStem newTokens) {
        if (newTokens.containsKey("access_token")) {
            QDLStem at = newTokens.getStem("access_token");
            clcCommands.getDummyAsset().setAccessToken(stemToAT(at));
        }
        if (newTokens.containsKey("refresh_token")) {
            QDLStem at = newTokens.getStem("refresh_token");
            clcCommands.getDummyAsset().setRefreshToken(stemToRT(at));
        }
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
                if (!initCalled) {
                    QDLCLC qdlclc = new QDLCLC(null);
                    OA2CommandLineClient.setInstance(qdlclc);
                }
                DebugUtil.setEnabled(true);
                clcCommands = new OA2CLCCommands(true, state.getLogger(), new QDLCLC(state.getLogger()));
                // note that the order of the arguments swaps.
                InputLine inputLine = new InputLine(DUMMY_ARG + " " + objects[1].toString() + "  " + objects[0].toString());
                clcCommands.load(inputLine);
                initCalled = true;
            } catch (Throwable e) {
                e.printStackTrace();
                state.getLogger().error("error initializing client for name=" + objects[1] + ", config=" + objects[0], e);
                initCalled = false;
                clcCommands = null;
                if (DebugUtil.isEnabled()) {
                    e.printStackTrace();
                }
                throw e;
            }
            return true;
        }

        protected OA2ClientEnvironment createEnvironment(QDLStem ini, String name) {
            OA2ClientEnvironment ce = new OA2ClientEnvironment();
            ce.setScopes(ini.getStem("scopes").getQDLList());
            return ce;
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
        public Object evaluate(Object[] objects, State state) throws Throwable {
            QDLStem claims = new QDLStem();
            if (clcCommands.getIdToken() == null || clcCommands.getIdToken().getPayload() == null) {
                return claims;
            }
            JSONObject jsonObject = clcCommands.getIdToken().getPayload();
            claims.fromJSON(jsonObject);
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
        public Object evaluate(Object[] objects, State state) throws Throwable {
            QDLStem g = new QDLStem();
            clcCommands.grant(argsToInputLine(getName(), objects));
            if (clcCommands.getGrant() == null) {
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
            boolean verify = false;
            boolean rawResponse = false;
            if (objects.length == 1) {
                if (objects[0] instanceof QDLStem) {
                    QDLStem input = (QDLStem) objects[0];
                    if (input.containsKey("verify")) {
                        verify = input.getBoolean("verify");
                    }
                    if (input.containsKey("raw_response")) {
                        rawResponse = input.getBoolean("raw_response");
                    }
                }
            }
            if (!verify) {
                args = args + " " + clcCommands.NO_VERIFY_JWT;
            }

            clcCommands.access(new InputLine(args));
            if (rawResponse) {
                QDLStem out = new QDLStem();
                try {
                    JSONObject jsonObject = JSONObject.fromObject(clcCommands.getCurrentATResponse().getRawResponse());
                    out.fromJSON(jsonObject);
                    return out;
                } catch (Throwable t) {

                }
                return clcCommands.getCurrentATResponse().getRawResponse();
            }
            return getTokens();
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            switch (argCount) {
                case 0:
                    doxx.add(getName() + "() get the access token, verifying the response. This returns the tokens.");
                    break;
                case 1:
                    doxx.add(getName() + "(arg.) get the access token, using the stem entries to construct the response.");
                    String bb = StringUtils.getBlanks(getName().length() + 1);
                    doxx.add("\nThe elements of the arg. stem are:\n");
                    doxx.add("      verify (boolean) - if true (default, verify the tokens");
                    doxx.add("raw_response (boolean) - if false, return the raw response. If true (default) return the actual tokens.");
                    break;
            }
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    protected String GET_CERT_NAME = "get_cert";

    public class GetCert implements QDLFunction {
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
            if (clcCommands.hasX509Certificates()) {
                return clcCommands.getX509CertificateString();
            }
            return "";
        }

        List<String> dd = new ArrayList<>();

        @Override
        public List<String> getDocumentation(int argCount) {
            if (dd.isEmpty()) {
                dd.add(getName() + "() - get a certificate (chain).");
                dd.add("Note that the client must be configured with the correct getcert scope and the");
                dd.add("server must support MyProxy.");
            }
            return dd;
        }
    }

    protected String CURRENT_URI = "current_uri";

    public class GetCurrentURI implements QDLFunction {
        @Override
        public String getName() {
            return CURRENT_URI;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0};
        }

        @Override
        public Object evaluate(Object[] objects, State state) throws Throwable {
            checkInit();
            URI c = clcCommands.getCurrentURI();
            if (c == null) {
                return QDLNull.getInstance();
            }
            return c.toString();
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> d = new ArrayList<>();
            d.add(getName() + "() - get the current URI or null if there is none");
            d.add("You should call " + URI_NAME + " first.");
            return d;
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
        public Object evaluate(Object[] objects, State state) throws Throwable {
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
        public Object evaluate(Object[] objects, State state) throws Throwable {
            checkInit();
            //clcCommands.refresh(argsToInputLine(getName(), objects));
            clcCommands.refresh();
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

    protected String ECHO_HTTP_RESPONSE = "echo_http_response";

    public class EchoHttpResponse implements QDLFunction {
        @Override
        public String getName() {
            return ECHO_HTTP_RESPONSE;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0, 1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) throws Throwable {
            if (objects.length == 0) {
                return ServiceClient.ECHO_RESPONSE;
            }
            if (!(objects[0] instanceof Boolean)) {
                throw new IllegalArgumentException(getName() + " requires a boolean argument");
            }

            Boolean oldValue = ServiceClient.ECHO_RESPONSE;
            ServiceClient.ECHO_RESPONSE = (Boolean) objects[0];
            return oldValue;
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            switch (argCount) {
                case 0:
                    doxx.add(getName() + "() - query current state of response echoing.");
                    doxx.add("Returns true is enabled, false otherwise.");
                case 1:
                    doxx.add(getName() + "( true | false) - set current state of response echoing.");
                    doxx.add("Returns previous state.");
            }
            doxx.add("HTTP response echoing means that *every* HTTP response to the server is echoed to the command");
            doxx.add("console (not to the GUI output). This is intended to allow very low-level");
            doxx.add("observation of this module.");
            doxx.add("See also:" + ECHO_HTTP_REQUEST);
            return doxx;
        }
    }

    protected String ECHO_HTTP_REQUEST = "echo_http_request";

    public class EchoHTTPRequest implements QDLFunction {
        @Override
        public String getName() {
            return ECHO_HTTP_REQUEST;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0, 1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) throws Throwable {
            if (objects.length == 0) {
                return ServiceClient.ECHO_REQUEST;
            }
            if (!(objects[0] instanceof Boolean)) {
                throw new IllegalArgumentException(getName() + " requires a boolean argument");
            }

            Boolean oldValue = ServiceClient.ECHO_REQUEST;
            ServiceClient.ECHO_REQUEST = (Boolean) objects[0];
            return oldValue;
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            switch (argCount) {
                case 0:
                    doxx.add(getName() + "() - query current state of request echoing.");
                    doxx.add("Returns true is enabled, false otherwise.");
                case 1:
                    doxx.add(getName() + "( true | false) - set current state of request echoing.");
                    doxx.add("Returns previous state.");
            }
            doxx.add("Request echoing means that *every* HTTP request to the server is echoed to the command");
            doxx.add("console (not to the GUI output). This is intended to allow very low-level");
            doxx.add("observation of this module. Crafting OAuth requests can be enormously difficult,");
            doxx.add("so if you need to see the traffic, this is invaluable.");
            doxx.add("See also:" + ECHO_HTTP_RESPONSE);

            return doxx;
        }
    }

    protected String EXCHANGE_NAME = "exchange";
    protected String EXCHANGE_RAW_RESPONSE = "raw_response";

    public class Exchange implements QDLFunction {
        @Override
        public String getName() {
            return EXCHANGE_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0, 1, 2, 3, 4, 5, 6, 7}; // just in case we need to pass lots
        }

        @Override
        public Object evaluate(Object[] objects, State state) throws Throwable {
            checkInit();
            InputLine inputLine = argsToInputLine(getName(), objects);
            boolean rawResponse = inputLine.hasArg(EXCHANGE_RAW_RESPONSE);
            inputLine.removeSwitch(EXCHANGE_RAW_RESPONSE);
            clcCommands.exchange(inputLine);
            if (Arrays.asList(objects).contains("-id")) {
                // if they request an id token, return it.
                QDLStem x = new QDLStem();
                x.fromJSON(clcCommands.getIdToken().getPayload());
                return x;
            }
            if (Arrays.asList(objects).contains("-rt")) {
                // if they request only a refresh token, return it.
                QDLStem x = new QDLStem();
                x.put("refresh_token", tokenToStem(clcCommands.getDummyAsset().getRefreshToken()));
                return x;
            }
            if (rawResponse) {
                QDLStem out = new QDLStem();
                out.fromJSON(clcCommands.getExchangeResponse());
                return out;
            }
            return getTokens();
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "([-rt | -at | -none] [-subject at|rt|id] [" + EXCHANGE_RAW_RESPONSE+"] Do the token exchange.");
            doxx.add("returns: Both tokens, but the requested token is updated.");
            doxx.add("Arguments:");
            doxx.add("(None) = exchange the access token using the access token as the bearer token. Make sure it has not expired.");
            doxx.add(EXCHANGE_RAW_RESPONSE + " = return the raw response from the server, not just the tokens.");
            doxx.add("-at = explicitly request an access token");
            doxx.add("-rt = exchange refresh token, using the refresh token as the bearer token");
            doxx.add("-none = do not request the return type, let the server use its default");
            doxx.add("-subject = Use the indicated token as the subject. The default is to use the requested type.");
            doxx.add("E.g.");
            doxx.add("exchange('-at', '-subject', 'rt');");
            doxx.add("would exchange the access token (possibly expired) using the (valid) refresh token.");
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
        InputLine inputLine = new InputLine(strings);
        return inputLine;
    }

    protected void handleException(Throwable t) {
        if (DebugUtil.isEnabled()) {
            t.printStackTrace();
        }
        if (t instanceof RuntimeException) {
            throw (RuntimeException) t;
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
        public Object evaluate(Object[] objects, State state) throws Throwable {
            checkInit();
            clcCommands.revoke(argsToInputLine(getName(), objects));
            return Boolean.TRUE;
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
            doxx.add(getName() + "() - initiate the device flow. If possible, the user code is copied to the clipboard.");
            doxx.add("This returns the raw response from the server");
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
            // remember that this call returns essentially a snapshot of the current user info on the
            // server. It is NOT an ID token or some such.
            org.oa4mp.delegation.server.UserInfo userInfo = clcCommands.user_info2(argsToInputLine(getName(), objects));
            JSONObject json = new JSONObject();
            json.putAll(userInfo.getMap());
            out.fromJSON(json);
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
            return new int[]{0, 1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            checkInit();
            if (objects.length == 0) {
                return getTokens();
            }
            if (!(objects[0] instanceof QDLStem)) {
                throw new IllegalArgumentException("the argument to " + getName() + " must be a stem");
            }
            setTokens((QDLStem) objects[0]);
            return Boolean.TRUE;
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            if (argCount == 0) {
                doxx.add(getName() + "() - return the current tokens.");
            }
            if (argCount == 1) {
                doxx.add(getName() + "(new_tokens.) - set the current access and refresh tokens");
                doxx.add("Note that the stem has keys access_token and refresh_token and these entries");
                doxx.add("are identical to the values returned by various calls. The output is true if successful.");
            }
            doxx.add("note that " + getName() + "(" + getName() + ") will set the tokens to the current tokens.");
            doxx.add("so this shows what the argument can be. A common construct is along the lines of");
            doxx.add("E.g.");
            doxx.add("old. := " + getName() + "();");
            doxx.add("//// Do a bunch of other stuff, like refreshes, exchanges and invalidate tokens");
            doxx.add(getName() + "(old.)");
            doxx.add("Sets the tokens to the value so you can resume your flow with them.");
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
            checkInit();
            // Assume that the clc has been initialized first since otherwise it is impossible to load
            // the file (e.g. assetStore is missing, debugger is missing etc.)
            clcCommands.read(argsToInputLine(getName(), objects));
            initCalled = true;
            return Boolean.TRUE;
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            switch (argCount) {
                case 1:
                    doxx.add(getName() + "(file) - read state previously saved by this client.");
                    break;
                case 2:
                    doxx.add(getName() + "(file, '-p') - provision current client from this saved state (used by ersatz clients).");
                    break;
            }
            doxx.add("NOTE: If you are going to read a configuration, make sure you initialize it first so that");
            doxx.add("the asset store etc. are all found.");
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
    protected static final String PARAM_FLAG_EXCHANGE_SHORT = "x";

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
     * This is rather similar to the {@link OA2CLCCommands#printToken(TokenImpl, boolean, boolean)}  and similar
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
        if (stem.containsKey("raw_token")) {
            return TokenFactory.createAT(stem.getString("raw_token"));
        }
        if (stem.containsKey("jti")) {
            return TokenFactory.createAT(stem.getString("jti"));
        }
        throw new IllegalArgumentException("Incorrect access token stem. Cannot create access token");
        //return new AccessTokenImpl(stem.getString("raw_token"), URI.create(stem.getString("jti")));
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
        if (stem.containsKey("raw_token")) {
            return TokenFactory.createRT(stem.getString("raw_token"));
            //  return new RefreshTokenImpl(stem.getString("raw_token"), URI.create(stem.getString("jti")));
        }
        if (stem.containsKey("jti")) {
            return TokenFactory.createRT(stem.getString("jti"));
        }
        throw new IllegalArgumentException("Incorrect refresh token stem. Cannot create refresh token");
        //return new RefreshTokenImpl(stem.getString("raw_token"), URI.create(stem.getString("jti")));
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

    public class RFC7523 implements QDLFunction {
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
            Map parameters = argToMap(objects, getName());
            clcCommands.rfc7523(parameters);

            return getTokens();
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> dd = new ArrayList<>();
            switch (argCount) {
                case 0:
                    dd.add(getName() + "() - issue grant request using default, 'username' is the client ID");
                    dd.add("E.g.");
                    dd.add(getName() + "()");
                    dd.add("Sends a basic request with no additional parameters. Returns the tokens and claims");
                    break;
                case 1:
                    dd.add(getName() + "(username | arg.) - issue grant request using the username or the entries of arg.");
                    dd.add("   The keys and values of arg. are sent as parameters, so be sure that values are strings.");
                    dd.add("\nE.g. with parameters");
                    dd.add(getName() + "('igwn-robot@bigstate.edu')");
                    dd.add("Sends request with the user name (as the subject of the request token). This is used on the");
                    dd.add("service as if the user logged in with the given name, so all e.g. QDL scripts will run against that name.");
                    dd.add("\nE.g.");
                    dd.add(getName() + "({'sub':'bob@bigstate.edu','lifetime':1000000})");
                    dd.add("sends the request with the given user name and the parameter (in this case, requesting a certificate lifetime).");
                    break;
            }

            return dd;
        }
    }

    private static Map argToMap(Object[] objects, String name) {
        Map parameters = new HashMap();
        if (objects.length == 1) {
            if (objects[0] instanceof String) {
                parameters.put(OA2Claims.SUBJECT, objects[0]);
            } else {
                if (objects[0] instanceof QDLStem) {
                    QDLStem stem = (QDLStem) objects[0];
                    for (Object key : stem.keySet()) {
                        Object value = stem.get(key);
                        if (value instanceof QDLStem) {
                            QDLStem qdlStem = (QDLStem) value;
                            if (qdlStem.isList()) {
                                JSONArray array = new JSONArray();
                                array.addAll(qdlStem.getQDLList());
                                parameters.put(key, array);
                            } else {
                                throw new IllegalArgumentException("General stems are not supported as values, just lists");
                            }
                        } else {
                            parameters.put(key, value);
                        }
                    }
                } else {
                    throw new IllegalArgumentException("unknown argument type for " + name);
                }
            }
        }
        return parameters;
    }

    public static String VERBOSE_ON = "verbose_on";

    public class VerboseOn implements QDLFunction {
        @Override
        public String getName() {
            return VERBOSE_ON;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0, 1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) throws Throwable {
            checkInit();
            if (objects.length == 0) {
                return clcCommands.isVerbose();
            }
            boolean oldValue = clcCommands.isVerbose();
            if (objects[0] instanceof Boolean) {
                clcCommands.set_verbose_on(new InputLine(((Boolean) objects[0]) ? "true" : "false"));
                return oldValue;
            }
            throw new IllegalArgumentException("unknown argument for " + getName() + " of type " + (objects[0].getClass().getSimpleName()));
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> dd = new ArrayList<>();
            if (argCount == 0) {
                dd.add(getName() + "() = query if verbose is on or not");
            }
            if (argCount == 1) {
                dd.add(getName() + "(true|false) = toggle if verbose is on or not");
            }
            dd.add("verbose refers to printing a great deal of internal information of the workings ");
            dd.add("of the CLC. Use it only if there is an issue that requires it");
            return dd;
        }
    }

    public static String JAVA_TRACE = "java_trace";

    public class JavaTrace implements QDLFunction {
        @Override
        public String getName() {
            return JAVA_TRACE;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0, 1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) throws Throwable {
            checkInit();
            boolean oldValue = DebugUtil.isEnabled() && DebugUtil.getDebugLevel() == DebugConstants.DEBUG_LEVEL_TRACE;
            if (objects.length == 0) {
                return oldValue;
            }
            if (objects[0] instanceof Boolean) {
                if ((Boolean) objects[0]) {
                    DebugUtil.setEnabled(true);
                    DebugUtil.setDebugLevel(DebugUtil.DEBUG_LEVEL_TRACE);
                } else {
                    DebugUtil.setEnabled(false);
                    DebugUtil.setDebugLevel(DebugUtil.DEBUG_LEVEL_OFF);
                }
                return oldValue;
            }
            throw new IllegalArgumentException("unknown argument for " + getName() + " of type " + (objects[0].getClass().getSimpleName()));

        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> dd = new ArrayList<>();
            if (argCount == 0) {
                dd.add(getName() + "() = query if java stack trace is on or not");
            }
            if (argCount == 1) {
                dd.add(getName() + "(true|false) = toggle java stack traces");
            }
            dd.add("This is used for low-level debugging of Java, such as module development.");
            dd.add("Unless you are a Java developer enabling it might result in out that does not make a lot of sense");
            return dd;
        }
    }

    public static String CLIENT_CREDENTIALS_FLOW = "ccf";
    public static String CLIENT_CREDENTIALS_RFC7523 = "rfc7523";

    public class ClientCredentialsFlow implements QDLFunction {
        @Override
        public String getName() {
            return CLIENT_CREDENTIALS_FLOW;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0, 1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) throws Throwable {
            checkInit();
            Boolean useRFC7523 = Boolean.FALSE;
            if (0 < objects.length && (objects[0] instanceof QDLStem)) {
                QDLStem inStem = (QDLStem) objects[0];
                useRFC7523 = inStem.containsKey(CLIENT_CREDENTIALS_RFC7523);
                if (useRFC7523) {
                    useRFC7523 = inStem.getBoolean(CLIENT_CREDENTIALS_RFC7523);
                    inStem.remove(CLIENT_CREDENTIALS_RFC7523);
                }
            }
            Map parameters = argToMap(objects, getName());
            clcCommands.ccf(parameters, useRFC7523);
            QDLStem QDLStem = new QDLStem();
            if (clcCommands.getCcfResponse() != null) {
                QDLStem.fromJSON(clcCommands.getCcfResponse());
            }
            return QDLStem;
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            switch (argCount) {
                case 0:
                    doxx.add(getName() + "() - initiate basic client credentials flow.");
                    break;
                case 1:
                    String bb = StringUtils.getBlanks(getName().length());
                    doxx.add(getName() + "(username | arg.) - initiate basic client credentials flow, using a subject or arguments.");
                    doxx.add(bb + "If the subject is supplied, it will be used as the subject of the");
                    doxx.add(bb + "ID token.");
                    doxx.add(bb + "If you supply the key " + CLIENT_CREDENTIALS_RFC7523 + " with a true value, then");
                    doxx.add(bb + "RFC7523 credentials are used. If false (default) or omitted, then the standard  id + secret is used.");
                    break;
            }
            doxx.add("This returns the raw response as a JSON object. To get the tokens or claims, use the");
            doxx.add("API calls, e.g. clc#tokens()");
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    @Override
    public JSONObject serializeToJSON() {
        if (clcCommands == null) {
            // nothing to serialize since it has not been initialized yet
            // But this might be called when it is first gotten from the symbol
            // table.
            return new JSONObject();
        }
        return clcCommands.toJSON();
    }

    @Override
    public void deserializeFromJSON(JSONObject jsonObject) {
        try {
            clcCommands.fromJSON(jsonObject);
        } catch (Throwable t) {
            if (t instanceof RuntimeException) {
                throw (RuntimeException) t;
            }
            throw new RuntimeException("error loading stored CLC state", t);
        }
    }
}
