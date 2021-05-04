package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.client.AssetResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStoreUtil;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.RFC8628Constants2;
import edu.uiuc.ncsa.myproxy.oa4mp.server.testing.CLCCommands;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2Asset;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientEnvironment;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2MPService;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.DateUtils;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.client.request.RTResponse;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.delegation.token.Token;
import edu.uiuc.ncsa.security.delegation.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.security.delegation.token.impl.AuthorizationGrantImpl;
import edu.uiuc.ncsa.security.delegation.token.impl.RefreshTokenImpl;
import edu.uiuc.ncsa.security.delegation.token.impl.TokenUtils;
import edu.uiuc.ncsa.security.oauth_2_0.JWTUtil;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.UserInfo;
import edu.uiuc.ncsa.security.oauth_2_0.client.ATResponse2;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.JWTUtil2;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims;
import edu.uiuc.ncsa.security.servlet.ServiceClientHTTPException;
import edu.uiuc.ncsa.security.util.cli.ConfigurableCommandsImpl;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import edu.uiuc.ncsa.security.util.pkcs.CertUtil;
import net.sf.json.JSONObject;
import org.apache.commons.codec.binary.Base64;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.io.*;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.List;
import java.util.*;

import static edu.uiuc.ncsa.security.core.util.StringUtils.isTrivial;
import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.ID_TOKEN;
import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.RAW_ID_TOKEN;
import static edu.uiuc.ncsa.security.oauth_2_0.jwt.JWTUtil2.PAYLOAD_INDEX;
import static edu.uiuc.ncsa.security.oauth_2_0.server.RFC8628Constants.*;

/**
 * A command line client. Invoke help as needed, but the basic operation is to create the initial
 * request url using the {@link #set_uri(InputLine)} call, paste it in your browser, authenticate
 * (since this is an OIDC client, you must pass through a browser at some point). The call back should
 * fail, so you copy the attempted callback from the service using the {@link #get_grant(InputLine)}
 * call. You can then do whatever you needed (get an access token, get refresh tokens if the server supports it)
 * inspect id tokens and such.
 * <p>Created by Jeff Gaynor<br>
 * on 5/11/16 at  2:57 PM
 */
public class OA2CLCCommands extends CLCCommands {

    public static final String IS_RFC_8628_KEY = "is_rfc8628";

    public OA2CLCCommands(MyLoggingFacade logger,
                          OA2CommandLineClient oa2CommandLineClient) throws Exception {
        super(logger, null);
        try {
            setCe((ClientEnvironment) oa2CommandLineClient.getEnvironment());
        } catch (Throwable t) {
            say("No configuration loaded.");
        }
        this.oa2CommandLineClient = oa2CommandLineClient;
        say(hasClipboard() ? "clipboard is supported." : "no clipboard support available.");
    }


    public String getConfigFile() {
        return configFile;
    }

    public void setConfigFile(String configFile) {
        this.configFile = configFile;
    }

    String configFile;
    protected OA2MPService service;

    protected OA2MPService getOA2S() {
        return (OA2MPService) getService();
    }

    @Override
    public OA2MPService getService() {
        if (service == null) {
            service = new OA2MPService(getCe());
        }
        return service;
    }

    public void getURIHelp() {
        say("set_uri");
        say("Usage: This will create the correct URL. If possible, it will put it in the clipboard.");
        sayi("Create the uri using the  client's configuration");
        sayi("This will put this in to the clipboard if possible.");
        sayi("This URL should be pasted exactly into the location bar.");
        sayi("You must then authenticate. After you authenticate, the");
        sayi("service will attempt a call back to a client endpoint which will");
        sayi("fail (this is the hook that lets us do this manually).");
        sayi("Next Step: You should invoke setgrant with the callback uri from the server.");
        say("See also: set_param");
    }

    SecureRandom secureRandom = new SecureRandom();

    protected String getRandomString() {
        long ll = secureRandom.nextLong();
        return Long.toHexString(ll);
    }

    String CLIENT_CFG_NAME_KEY = "-name";


    OA2CommandLineClient oa2CommandLineClient;

    public void load(InputLine inputLine) throws Exception {
        if (!inputLine.hasArgs()) {
            say("config file = " + oa2CommandLineClient.getConfigFile() + ", config name=" + oa2CommandLineClient.getConfigName());
            sayi("Usage: load a configuration from a file and make it active.");
            sayi("Remember that loading a configuration clears all current state, except parameters.");
            return;
        }
        try {
            oa2CommandLineClient.load(inputLine);
        } catch (ConfigurableCommandsImpl.ListOnlyNotification listOnlyNotification) {
            // This just means we added an out of band way to list. If we don't exit here
            // we will clear the state no matter what the user requested.
            return;
        }
        if (showHelp(inputLine)) {
            return;
        }
        clear(inputLine); // only thing used in clear is --help. If that is present won't get here.
        setCe((ClientEnvironment) oa2CommandLineClient.getEnvironment());
        service = null;
    }

    boolean isDeviceFlow = false;
    String deviceFlowCallback;

    public void df(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            say("df");
            sayi("Usage: Initiate the device flow for this client");
            sayi("You will need to use a browser and the returned user code to authenticate. Then");
            sayi("you can get that access token with the get_at command. This client does not");
            sayi("do polling.");
            sayi("See also: get_at");
            return;
        }
        // set up for the next round
        clear(inputLine, false);
        if (getCe() == null) {
            say("sorry, but you have no loaded a configuration yet.");
            return;
        }
        dummyAsset = (OA2Asset) getCe().getAssetStore().create();

        OA2ClientEnvironment oa2ce = (OA2ClientEnvironment) getCe();
        String requestString = oa2ce.getDeviceAuthorizationUri().toString();
        requestString = requestString + "?" + OA2Constants.CLIENT_ID + "=" + oa2ce.getClientId();
        String rawResponse = getService().getServiceClient().getRawResponse(requestString,
                oa2ce.getClient().getIdentifierString(),
                oa2ce.getClient().getSecret());
        try {
            JSONObject resp = JSONObject.fromObject(rawResponse);
            deviceFlowCallback = resp.getString(RFC8628Constants2.VERIFICATION_URI);
            say("please go to :" + deviceFlowCallback);
            userCode = resp.getString(RFC8628Constants2.USER_CODE);
            deviceCode = resp.getString(DEVICE_CODE);
            say("user code: " + userCode);
            say("code valid for " + resp.getLong(RFC8628Constants2.EXPIRES_IN) + " sec.");
            copyToClipboard(userCode, "user code copied to clipboard");
            isDeviceFlow = true;
            grant = new AuthorizationGrantImpl(URI.create(resp.getString(RFC8628Constants2.DEVICE_CODE)));
        } catch (Throwable t) {
            say("sorry but the response from the service was not understood:" + rawResponse);
            if (DebugUtil.isEnabled()) {
                t.printStackTrace(); // in case /trace on
            }
        }
    }

    String userCode;
    String deviceCode;
    /**
     * What is currently from the {@link #set_uri(InputLine)}.
     */
    URI currentURI;

    /**
     * Constructs the URI
     *
     * @param inputLine
     * @throws Exception
     */
    public void set_uri(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            getURIHelp();
            return;
        }
        if (getCe() == null) {
            say("Oops! No configuration has been loaded.");
            return;
        }
        // Maybe one of these days allow for it all in one swoop. Lots of state to change though...
        // And in particular, if there are issues (wrong config name) then hard to handle errors here.

/*        if (inputLine.hasArg(CLIENT_CFG_NAME_KEY)) {
            String name = inputLine.getNextArgFor(CLIENT_CFG_NAME_KEY);
            say("...loading configuration named \"" + name + "\"");
            try {
                ConfigurationNode node = ConfigUtil.findConfiguration(getConfigFile(),
                        name,
                        ClientXMLTags.COMPONENT);
                OA2ClientLoader loader = new OA2ClientLoader(node);
                service = new OA2MPService(loader.load());
            } catch (Throwable t) {
                say("Sorry, I could not find the configuration with id =\"" + name + "\":" + t.getMessage());
            }
        }*/
        clear(inputLine, false); //clear out everything except any set parameters
        Identifier id = AssetStoreUtil.createID();
        OA4MPResponse resp = getService().requestCert(id, requestParameters);
        DebugUtil.trace(this, "client id = " + getCe().getClientId());
        currentURI = resp.getRedirect();

        dummyAsset = (OA2Asset) getCe().getAssetStore().get(id.toString());
        copyToClipboard(currentURI.toString(), "URL copied to clipboard:");
        say(currentURI.toString());
    }

    protected void copyToClipboard(String target, String s) {
        try {
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            if (clipboard != null) {
                StringSelection data = new StringSelection(target);
                clipboard.setContents(data, data);
                say(s);
            }
        } catch (Throwable t) {
            // there was a problem with the clipboard. Skip it.
        }
    }

    protected String getFromClipboard(boolean silentMode) {
        // TODO Places where the clipboard is read have a lot of cases of prompting the user for the information. Refactor that to use this method?
        try {
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            return (String) clipboard.getData(DataFlavor.stringFlavor);
        } catch (Throwable t) {

        }
        return null;
    }

    /**
     * Peeks into clipboard to see if it is there and actually works. This is far from a perfect test
     * since it only looks for a string in the clipboard, but actually testing every case for a supported
     * flavor would be much more of a task.
     *
     * @return
     */
    protected boolean hasClipboard() {
        // Annoying thing #42. we check if the clipboard exists by trying to read from it
        // this is the most reliable cross platform way to do it. The problem is that
        // error messages can be generated very deep in the stack that cannot be intercepted
        // with a try...catch block and sent to std err. So we have to turn redirect the error
        // then reset the std err. Pain in the neck, but users should not see large random
        // stack traces that the last thing someone left on their clipboard can't be
        // easily converted to a string.
        PrintStream errStream = System.err;
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        System.setErr(new PrintStream(byteArrayOutputStream));

        try {
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.getData(DataFlavor.stringFlavor);
            System.setErr(errStream);
            return true;
        } catch (Throwable t) {
            info("Probably benign message from checking clipboard:" + new String(byteArrayOutputStream.toByteArray()));
        }
        System.setErr(errStream);
        return false;

    }

    protected String createURI(String base, HashMap<String, String> args) throws UnsupportedEncodingException {
        String uri = base;
        boolean firstPass = true;
        for (String key : args.keySet()) {
            String value = args.get(key);
            uri = uri + (firstPass ? "?" : "&") + key + "=" + encode(value);
            if (firstPass) firstPass = false;
        }
        canGetGrant = true;
        return uri;
    }

    static String encoding = "UTF-8";

    String encode(String x) throws UnsupportedEncodingException {
        if (x == null) return "";
        return URLEncoder.encode(x, encoding);
    }

    String decode(String x) throws UnsupportedEncodingException {
        if (x == null) return "";
        return URLDecoder.decode(x, encoding);
    }

    AuthorizationGrantImpl grant;

    protected void printGrant() {
        if (grant == null) {
            say("no grant");
            return;
        }
        if (TokenUtils.isBase32(grant.getToken())) {
            say("raw grant = " + grant.getToken());
        }
        say("    grant = " + (grant.getJti()));
    }

    public void get_grant(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            setGrantHelp();
            return;
        }
        if (getCe() == null) {
            say("Oops! No configuration has been loaded.");
            return;
        }
        String x = null;
        if (inputLine.size() == 1) {
            if (grant != null) {
                // already have a grant. Show it and copy it to the clipboard
                printGrant();
                copyToClipboard(grant.getJti().toString(), "grant copied to clipboard");
                return;
            }
            // no arg. get it from the clipboard
            try {
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                x = (String) clipboard.getData(DataFlavor.stringFlavor);
            } catch (Throwable t) {
                say("No clipboard.");
                x = getInput("Enter the callback", "");
                if (isTrivial(x)) {
                    say("aborted");
                    return;
                }
            }
        } else {

            x = inputLine.getArg(1); // zero-th element is the name of this function. 1st is the actual argument.
        }
        if (isTrivial(x)) {
            say("(no grant)");
            return;
        }
        // now we parse this.
        if (!x.startsWith(getCe().getCallback().toString())) {
            say("The callback in the configuration does not match that in the argument you gave");
            return;
        }
        String args = x.substring(x.indexOf("?") + 1); // skip the ? in the substring.
        StringTokenizer st = new StringTokenizer(args, "&");
        boolean gotGrant = false;
        boolean gotError = false;
        String errorCode = "";
        String errorDescription = "";
        while (st.hasMoreTokens()) {
            String current = st.nextToken();
            if (current.startsWith(OA2Constants.ERROR + "=")) {
                gotError = true;
                errorCode = current.substring(OA2Constants.ERROR.length() + 1);
            }

            if (current.startsWith(OA2Constants.ERROR_DESCRIPTION + "=")) {
                gotError = true;
                errorDescription = current.substring(OA2Constants.ERROR_DESCRIPTION.length() + 1);
            }

            if (current.startsWith(OA2Constants.AUTHORIZATION_CODE + "=")) {
                String raw = decode(current.substring(5));
                URI jti;
                if(TokenUtils.isBase32(raw)){
                    jti = URI.create(TokenUtils.b32DecodeToken(raw));
                }else{
                     jti = URI.create(raw);
                }
                grant = new AuthorizationGrantImpl(raw,jti);

                gotGrant = true;
                copyToClipboard(jti.toString(), "grant copied to clipboard.");
            }
        }
        if (gotError) {
            if (isTrivial(errorCode)) {
                say("Error! (no code)");
            } else {
                say("Error! The code is:" + errorCode);
            }
            if (!isTrivial(errorDescription)) {
                say("       description: " + URLDecoder.decode(errorDescription, "UTF-8"));
            }
            return;
        }
        if (gotGrant) {
            printGrant();
        } else {
            say("No grant found. Check the URL?");
        }
    }

    public OA2Asset getDummyAsset() {
        return dummyAsset;
    }

    public void clear(InputLine inputLine, boolean clearParams) throws Exception {
        if (showHelp(inputLine)) {
            getClearHelp();
            return;
        }
        dummyAsset = null;
        assetResponse = null;
        currentATResponse = null;
        currentURI = null;
        grant = null;
        rawIdToken = null;
        claims = null;

        canGetCert = false;
        canGetGrant = false;
        canGetRT = false;
        canGetAT = false;
        if (clearParams) {
            requestParameters = new HashMap<>();
            tokenParameters = new HashMap<>();
            exchangeParameters = new HashMap<>();
        }
        isDeviceFlow = false;
        userCode = null;
        deviceFlowCallback = null;
        deviceCode = null;
    }

    public static String CLEAR_PARAMETERS_FLAG = "-all";

    public void clear(InputLine inputLine) throws Exception {
        clear(inputLine, inputLine.hasArg(CLEAR_PARAMETERS_FLAG));
    }

    boolean canGetGrant = false;
    boolean canGetAT = false;
    boolean canGetCert = false;
    boolean canGetRT = false;

    protected void getClearHelp() {
        say("clear [" + CLEAR_PARAMETERS_FLAG + "]");
        sayi("Usage: Reset all internal state and restart.");
        sayi("You should do this rather than just starting over");
        sayi("as you may run into old state.");
        sayi(CLEAR_PARAMETERS_FLAG + " (optional) if true, will also clear all stored parameters.");
    }

    OA2Asset dummyAsset;

    protected void saveCertHelp() {
        say("save_cert filename:");
        sayi("Usage: This will save the cert to the filename.");
        sayi("Be sure to do a getcert call first so you have one.");
        sayi("Note that the filename must be fully qualified.");
        sayi("If there is no cert available, no file will be written, but a message will be printed.");
    }

    /**
     * If the state supports this, it will save the current cert to a file. The complete filename must be supplied,
     * including any path.
     *
     * @param inputLine
     * @throws Exception
     */
    public void save_cert(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            saveCertHelp();
            return;
        }
        if (assetResponse == null) {
            say("Sorry, but there is no cert to save. Please do a successful getcert call first.");
            return;
        }
        String cert = CertUtil.toPEM(assetResponse.getX509Certificates());
        if (!inputLine.hasArgs()) {
            say("Sorry. You did not specify a file so the cert cannot be saved.");
            return;
        }
        String fileName = inputLine.getArg(1);
        File file = new File(fileName);
        if (!file.isAbsolute()) {
            say("Sorry, you must supply a path.");
            return;
        }
        FileWriter fileWriter = new FileWriter(fileName);
        BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
        bufferedWriter.write(cert + "\n");
        bufferedWriter.flush();
        bufferedWriter.close();
        say("File \"" + file.getAbsolutePath() + "\" saved successfully.");
    }

    String rawIdToken = null;

    protected void showRawTokenHelp() {
        sayi("show_raw_id_token:");
        sayi("Usage: This will show the raw id token, i.e., the JWT. ");
        sayi("If you wish to see the contents of this JWT");
        sayi("you should probably invoke show_claims instead.");
        sayi("See also: show_claims");
    }

    public void show_raw_id_token(InputLine inputLine) throws Exception {
        if (grant == null || showHelp(inputLine)) {
            showRawTokenHelp();
            return;
        }

        if (rawIdToken == null) {
            sayi("No id token.");
            return;
        }
        if (rawIdToken.length() == 0) {
            sayi("Empty id token");
            return;
        }
        sayi(rawIdToken);
    }

    JSONObject claims = null;

    public void claims(InputLine inputLine) throws Exception {
        if (grant == null || showHelp(inputLine)) {
            showClaimsHelp();
            return;
        }
        if (claims == null || claims.isEmpty()) {
            say("(no claims found)");
        } else {
            say(claims.toString(2));
        }

    }

    protected void showClaimsHelp() {
        sayi("showClaims");
        sayi("Usage: This will show the most recent set of claims.");
        sayi(" You must get an access token before this is set.");
        sayi("You may also see the raw version of this (simply the JWT) by calling show_raw_token.");
        sayi("See also: get_at, get_rt, exchange");
    }

    protected void showRevokeHelp() {
        say("revoke -at | -rt");
        sayi("Usage: Revoke either the access token or the refresh token");
    }

    public void revoke(InputLine inputLine) throws Exception {
        if (grant == null || showHelp(inputLine)) {
            showRevokeHelp();
            return;
        }
        boolean revokeAT = inputLine.hasArg("-at");
        boolean revokeRT = inputLine.hasArg("-rt");
        say("under construction");

    }

    public void asset(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            say("asset");
            sayi("Usage: Show the current asset.");
            sayi("Asset refers to the internal state of this exchange.");
            sayi("Mostly this is used if you are trying to debug exactly what");
            sayi("the state of the exchange is. Other calls display parts of the asset.");
            sayi("See also: tokens, get_grant, claims");
            return;
        }
        if (getDummyAsset() == null) {
            say("no asset");
            return;
        }
        say(getDummyAsset().toJSON().toString(1));

    }

    public void get_at(InputLine inputLine) throws Exception {
        if (grant == null || showHelp(inputLine)) {
            getATHelp();
            return;
        }
        if (getCe() == null) {
            say("Oops! No configuration has been loaded.");
            return;
        }
        DebugUtil.trace(this, "Getting AT, grant=" + grant);
        if (!isDeviceFlow) {
            standard_get_at(inputLine);
        } else {
            df_get_at(inputLine);
        }

    }

    private void df_get_at(InputLine inputLine) {
        if (isDeviceFlow) {
            currentATResponse = getService().rfc8628Request(dummyAsset, deviceCode, tokenParameters);
            processATResponse(inputLine);
        } else {
            say("sorry, but there is no device flow active");
        }
    }

    private void standard_get_at(InputLine inputLine) {
        currentATResponse = getOA2S().getAccessToken(getDummyAsset(), grant, tokenParameters);
        processATResponse(inputLine);
    }

    private void processATResponse(InputLine inputLine) {
        if (getDummyAsset().getAccessToken().isOldVersion() && getDummyAsset().getAccessToken().getLifetime() < 0) {
            getDummyAsset().getAccessToken().setLifetime(OA2ConfigurationLoader.ACCESS_TOKEN_LIFETIME_DEFAULT);
        }
        if (getDummyAsset().getRefreshToken().isOldVersion() && getDummyAsset().getRefreshToken().getLifetime() < 0) {
            getDummyAsset().getRefreshToken().setLifetime(OA2ConfigurationLoader.MAX_REFRESH_TOKEN_LIFETIME_DEFAULT);
        }
        Object x = currentATResponse.getParameters().get(RAW_ID_TOKEN);
        if (x == null) {
            x = "";
        } else {
            rawIdToken = x.toString();
        }
        claims = (JSONObject) currentATResponse.getParameters().get(ID_TOKEN);
        if (inputLine.hasArg(CLAIMS_FLAG)) {

            if (claims.isEmpty()) {
                say("(no claims found)");
            } else {
                say(claims.toString(2));
            }
        }
        printTokens(inputLine.hasArg(NO_VERIFY_JWT));
    }

    ATResponse2 currentATResponse;

    protected void getCertHelp() {
        say("get_cert");
        sayi("Usage: This will get the requested cert chain from the server.");
    }

    protected void getUIHelp() {
        say("get_user_info");
        sayi("Usage: This will get the user info from the server.");
        sayi("You must have already authenticated");
        sayi("*and* gotten a valid access token by this point. Just a list of these it printed.");
        sayi("What is returned is dependant upon what the server supports.");
    }

    public void get_user_info(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            getUIHelp();
            return;
        }

        UserInfo userInfo = getOA2S().getUserInfo(dummyAsset.getIdentifier().toString());
        say("user info:");
        for (String key : userInfo.getMap().keySet()) {
            say("          " + key + " = " + userInfo.getMap().get(key));
        }

    }

    AssetResponse assetResponse = null;

    public void get_cert(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            getCertHelp();
            return;
        }
        if (getCe() == null) {
            say("Oops! No configuration has been loaded.");
            return;
        }
        assetResponse = getOA2S().getCert(dummyAsset, currentATResponse);
        if (assetResponse.getUsername() != null) {
            say("returned username=" + assetResponse.getUsername());
        }
        say("X509Certs:");
        say(CertUtil.toPEM(assetResponse.getX509Certificates()));

    }

    public static final String NO_VERIFY_JWT = "-no_verify";

    protected void getRTHelp() {
        say("get_rt [" + CLAIMS_FLAG + " | " + NO_VERIFY_JWT + "]:");
        sayi("Usage: Get new refresh and access tokens.");
        sayi("You must have already called get_at first *and* the server must issue refresh");
        sayi("tokens. This will print out a summary of the expiration time.");
        sayi(CLAIMS_FLAG + " = the id token will be printed");
        sayi(NO_VERIFY_JWT + " = do not verify JWTs against server. Default is to verify.");
        sayi("See also: get_at");
    }

    protected JSONObject resolveFromToken(Token token, boolean noVerify) {
        if (noVerify) {
            try {
                String[] components = JWTUtil.decat(token.getToken());
                return JSONObject.fromObject(new String(Base64.decodeBase64(components[PAYLOAD_INDEX])));
            } catch (Throwable t) {
                return null;
            }
        }
        JSONWebKeys keys = JWTUtil2.getJsonWebKeys(getService().getServiceClient(), ((OA2ClientEnvironment) getService().getEnvironment()).getWellKnownURI());
        try {
            JSONObject json = JWTUtil.verifyAndReadJWT(token.getToken(), keys);

            return json;
        } catch (Throwable t) {
            // do nothing.
        }
        return null;

    }

    public void authz(InputLine inputLine) throws Exception {
        String rawResponse = null;
        try {
            if (inputLine.hasArgs()) {
                rawResponse = getService().getServiceClient().getRawResponse(inputLine.getLastArg());
            } else {
                if (currentURI == null) {
                    say("sorry, you did not specify a URL and no default was found.");
                    return;
                } else {
                    rawResponse = getService().getServiceClient().getRawResponse(currentURI.toString());
                }

            }

        } catch (ServiceClientHTTPException t) {
            if (t.getMessage().contains("requires HTTP authentication")) {
                say("Request ok, but this requires authentication to continue");
                return;
            }
        }
        if (rawResponse == null) {
            say("(no response)");
        } else {
            say(rawResponse);
        }
    }

    public void tokens(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            showTokensHelp();
            return;
        }
        printTokens(inputLine.hasArg(NO_VERIFY_JWT));
    }

    private void showTokensHelp() {
        say("tokens [" + NO_VERIFY_JWT + "]");
        sayi("Usage: Print the current list of tokens");
        sayi(NO_VERIFY_JWT + " = do not verify JWTs against server. Default is to verify.");
        sayi("Note: If the token has expired, then verification will fail and nothing will be");
        sayi("displayed.");
    }

    protected void printToken(AccessToken accessToken, boolean noVerify) {

        if (accessToken != null) {
            JSONObject token = null;
            // If the access token is a jwt
            try {
                token = resolveFromToken(accessToken, noVerify);
            } catch (Throwable t) {
                say("service is unreachable -- cannot verify token.");
                return;
            }
            if (token == null) {
                say("access token = " + accessToken.getToken());
                if (TokenUtils.isBase32(accessToken.getToken())) {
                    // Or we over-write the access token and lose base 64 encoding.
                    AccessTokenImpl accessToken2 = new AccessTokenImpl(null);

                    accessToken2.decodeToken(accessToken.getToken());
                    accessToken = accessToken2;
                    say("   decoded token:" + accessToken.getToken());
                }
                Date startDate = DateUtils.getDate(accessToken.getToken());
                startDate.setTime(startDate.getTime() + accessToken.getLifetime());
                if (startDate.getTime() < System.currentTimeMillis()) {
                    say("   token expired \n");
                } else {
                    say("   expires in = " + accessToken.getLifetime() + " ms.");
                    say("   valid until " + startDate + "\n");
                }
            } else {
                sayi("JWT access token:" + token.toString(1));
                AccessTokenImpl at = (AccessTokenImpl) accessToken;
                if (token.containsKey(OA2Claims.EXPIRATION)) {
                    Date d = new Date();
                    d.setTime(token.getLong(OA2Claims.EXPIRATION) * 1000L);

                    at.setLifetime(d.getTime() - System.currentTimeMillis());
                    if (at.getLifetime() <= 0) {
                        say("   token expired \n");
                    } else {
                        say("   expires in = " + at.getLifetime() + " ms.\n");
                    }
                }
            }
        }

    }

    protected void printToken(RefreshTokenImpl refreshToken, boolean noVerify) {
        if (refreshToken != null) {
            JSONObject token = null;
            try {
                token = resolveFromToken(refreshToken, noVerify);
            } catch (Throwable t) {
                say("service is unreachable -- cannot verify token.");
                return;
            }
            if (token == null) {
                say("refresh token = " + refreshToken.getToken());
                if (TokenUtils.isBase32(refreshToken.getToken())) {
                    RefreshTokenImpl refreshToken2 = new RefreshTokenImpl(null);

                    refreshToken2.decodeToken(refreshToken.getToken());
                    refreshToken = refreshToken2;
                    say("   decoded token:" + refreshToken.getToken());
                }
                Date startDate = DateUtils.getDate(refreshToken.getToken());
                startDate.setTime(startDate.getTime() + refreshToken.getLifetime());
                if (startDate.getTime() <= System.currentTimeMillis()) {
                    say("   token expired " + startDate + "\n");
                } else {
                    say("   expires in = " + refreshToken.getLifetime() + " ms.");
                    say("   valid until " + startDate + "\n");
                }

            } else {
                say("JWT refresh token = " + token.toString(1));
                if (token.containsKey(OA2Claims.EXPIRATION)) {
                    Date d = new Date();
                    d.setTime(token.getLong(OA2Claims.EXPIRATION) * 1000L);

                    refreshToken.setLifetime(d.getTime() - System.currentTimeMillis());
                    if (refreshToken.getLifetime() <= 0) {
                        say("   token expired\n");
                    } else {
                        say("   expires in = " + refreshToken.getLifetime() + " ms.");
                    }
                }
            }
        }
    }

    protected void printTokens(boolean noVerify) {
        // It is possible that the service is down in which case the tokens can't be verified.
        if (isVerbose() && currentURI != null) {
            say("Current request URI:");
            say(currentURI.toString());
        }
        printToken(getDummyAsset().getAccessToken(), noVerify);
        printToken(getDummyAsset().getRefreshToken(), noVerify);


    }

    public static final String CLAIMS_FLAG = "-claims";

    public void get_rt(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            getRTHelp();
            return;
        }
        if (getCe() == null) {
            say("Oops! No configuration has been loaded.");
            return;
        }
        RTResponse rtResponse = getOA2S().refresh(dummyAsset.getIdentifier().toString(), tokenParameters);
        dummyAsset = (OA2Asset) getCe().getAssetStore().get(dummyAsset.getIdentifier().toString());
        // Have to update the AT reponse here every time or no token state is preserved.
        currentATResponse = new ATResponse2(dummyAsset.getAccessToken(), dummyAsset.getRefreshToken());
        currentATResponse.setParameters(rtResponse.getParameters());
        JSONObject json = JSONObject.fromObject(currentATResponse.getParameters());
        claims = json;
        if (inputLine.hasArg(CLAIMS_FLAG)) {
            if (json.isEmpty()) {
                say("(no claims found)");
            } else {
                say(json.toString(2));
            }
        }
        printTokens(inputLine.hasArg(NO_VERIFY_JWT));
    }


    protected void getATHelp() {
        say("get_at [" + CLAIMS_FLAG + " | " + NO_VERIFY_JWT + "]:");
        sayi("Usage: Gets the access token and refresh token (if supported on");
        sayi("   the server) for a given grant. ");
        sayi("You must have already set the grant with the get_grant call.");
        sayi("A summary of the refresh token and its expiration is printed, if applicable.");
        sayi("" + CLAIMS_FLAG + " =  he id token will be printed");
        sayi("" + NO_VERIFY_JWT + " = do not verify JWTs against server. Default is to verify.");

    }

    protected void setGrantHelp() {
        say("get_grant [callback]:");
        sayi("Usage: Read the callback URL and process it into a grant, etc.");
        sayi("callback = the entire callback returned from the service");
        sayi("no arg -- either ");
        sayi("case A: you already have done this and a grant is set. Show it, paste it in the clipboard.");
        sayi("case B: No grant is set. Read the clipboard and set it from that.");
        sayi("The assumption is that you use seturi to get the correct authorization uri and have ");
        sayi("logged in. Your browser *should* have a callback to your client.");
        sayi("Copy that to the clipboard. If you call this with no argument, then the clipboard is read.");
        sayi("Otherwise paste the callback directly");
        sayi("See also: set_uri");
    }


    protected void exchangeHelp() {
        sayi("exchange [-at|-rt]");
        sayi("Usage: This will exchange the current access token (so you need to");
        sayi("   have gotten that far first) for a secure token.");
        sayi("The response will contain other information that will be displayed.");
        sayi("If there is no parameter, the current access token is used for the exchange");
        sayi("Otherwise you may specify -at to exchange the access token or -rt to exchange using the refresh token.");
        say("E.g.");
        sayi("exchange -at ");
        sayi("Note: you can only specify scopes for the access token. They are ignored for refresh tokens");
        say("See also: get_at, set_param to set additional parameters (like specific scopes or the audience");
    }

    JSONObject sciToken = null;

    public void exchange(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            exchangeHelp();
            return;
        }
        if (getCe() == null) {
            say("Oops! No configuration has been loaded.");
            return;
        }
        boolean didIt = false;
        if (1 == inputLine.size() || inputLine.hasArg("-at")) {
            // use the access token to get access token. This is legal in the spec
            // and this ensures it gets tested
            didIt = true;
            AccessTokenImpl accessToken = null;
            JSONObject token = resolveFromToken(getDummyAsset().getAccessToken(), true);
            if (token == null) {
                accessToken = getDummyAsset().getAccessToken();
            } else {
                accessToken = new AccessTokenImpl(getDummyAsset().getAccessToken().getToken(),
                        URI.create(token.getString(OA2Claims.JWT_ID)));
            }
            // Note in the next call, the asset is updated by the call since it has all of the information
            // for the token types. We just need to grab the raw token since we also stash it.
            JSONObject response = getService().exchangeRefreshToken(getDummyAsset(),
                    accessToken,
                    exchangeParameters,
                    true);
            sciToken = response;
            //    AccessTokenImpl newAt = new AccessTokenImpl(sciToken.getString(RFC8693Constants.ACCESS_TOKEN));
            //  newAt.isExpired()

            printToken(getDummyAsset().getAccessToken(), false);
        }
        
        if (inputLine.hasArg("-rt")) {
            didIt = true;
            RefreshTokenImpl rt = null;
            JSONObject token = resolveFromToken(getDummyAsset().getRefreshToken(), true);
            if (token == null) {
                rt = getDummyAsset().getRefreshToken();
            } else {
                rt = new RefreshTokenImpl(getDummyAsset().getRefreshToken().getToken(),
                        URI.create(token.getString(OA2Claims.JWT_ID)));
            }
            //RefreshToken rt = getDummyAsset().getRefreshToken();
            JSONObject response = getService().exchangeRefreshToken(getDummyAsset(), rt, null, false);
            sciToken = response;

            printToken(getDummyAsset().getRefreshToken(), false);
        }
        if (!didIt) {
            sayi("Sorry, argument not understood");
            exchangeHelp();
        }


    }

    protected String CONFIG_NAME_KEY = "config_name";
    protected String CONFIG_FILE_KEY = "config_file";
    protected String SYSTEM_MESSAGE_KEY = "system_message";
    protected String USER_MESSAGE_KEY = "user_message";
    protected String ASSET_KEY = "asset";
    protected String CLAIMS_KEY = "claims";
    protected String CURRENT_URI_KEY = "current_uri";
    protected String AUTHZ_GRANT_KEY = "authz_grant";
    protected String TOKEN_PARAMETERS_KEY = "token_parameters";
    protected String AUTHZ_PARAMETERS_KEY = "authz_parameters";
    protected String EXCHANGE_PARAMETERS_KEY = "exchange_parameters";
    protected String AT_RESPONSE_KEY = "at_response";


    public void read(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            showReadHelp();
            return;
        }
        if (0 == inputLine.getArgCount()) {
            if (saveFile == null) {
                say("sorry, but you must specify a file");
                return;
            }
        } else {
            saveFile = new File(inputLine.getLastArg());
        }

        if (!saveFile.exists()) {
            say("sorry, but \"" + saveFile.getAbsolutePath() + "\" does not exist");
            return;
        }
        if (saveFile.isDirectory()) {
            say("sorry, but \"" + saveFile.getAbsolutePath() + "\" is a directory");
            return;
        }

        StringBuffer stringBuffer = new StringBuffer();
        Path path = Paths.get(saveFile.getAbsolutePath());
        say("reading file \"" + saveFile.getAbsolutePath() + "\"");
        List<String> contents = Files.readAllLines(path);
        int i = 0;
        //Read from the stream
        for (String content : contents) {
            stringBuffer.append(content + "\n");
        }

        JSONObject json = JSONObject.fromObject(stringBuffer.toString());
        if (json.containsKey(CONFIG_FILE_KEY)) {
            // make a fake input line for loading the last configuration and run it.
            // Do this first since it clears the current state and anything loaded before it is lost.

            Vector v = new Vector();
            v.add("load");
            v.add(json.getString(CONFIG_NAME_KEY));
            v.add(json.getString(CONFIG_FILE_KEY));
            InputLine loadLine = new InputLine(v);
            load(loadLine);
        }

        if (json.containsKey(SYSTEM_MESSAGE_KEY)) {
            say(json.getString(SYSTEM_MESSAGE_KEY));
        }

        if (json.containsKey(USER_MESSAGE_KEY)) {
            lastUserMessage = json.getString(USER_MESSAGE_KEY);
            say(lastUserMessage);
        }
        if (json.containsKey(CLAIMS_KEY)) {
            claims = json.getJSONObject(CLAIMS_KEY);
        }
        if (json.containsKey(CURRENT_URI_KEY)) {
            currentURI = URI.create(json.getString(CURRENT_URI_KEY));
        }
        if (json.containsKey(AUTHZ_GRANT_KEY)) {
            grant = new AuthorizationGrantImpl(URI.create("a"));
            grant.fromJSON(json.getJSONObject(AUTHZ_GRANT_KEY));
        }


        if (json.containsKey(TOKEN_PARAMETERS_KEY)) {
            tokenParameters = new HashMap<>();
            tokenParameters.putAll(json.getJSONObject(TOKEN_PARAMETERS_KEY));
        }
        if (json.containsKey(AUTHZ_PARAMETERS_KEY)) {
            requestParameters = new HashMap<>();
            requestParameters.putAll(json.getJSONObject(AUTHZ_PARAMETERS_KEY));
        }

        if (json.containsKey(EXCHANGE_PARAMETERS_KEY)) {
            exchangeParameters = new HashMap<>();
            exchangeParameters.putAll(json.getJSONObject(EXCHANGE_PARAMETERS_KEY));
        }
        if (json.containsKey(AT_RESPONSE_KEY)) {
            JSONObject atr = json.getJSONObject(AT_RESPONSE_KEY);
            AccessTokenImpl ati = new AccessTokenImpl(null);
            ati.fromJSON(atr.getJSONObject("access_token"));
            RefreshTokenImpl rti = new RefreshTokenImpl(null);
            rti.fromJSON(atr.getJSONObject("refresh_token"));
            currentATResponse = new ATResponse2(ati, rti);
            if (atr.containsKey("parameters")) {
                currentATResponse.setParameters(atr.getJSONObject("parameters"));
            }
        }

        // RFC 8628 attributes
        isDeviceFlow = json.getBoolean(IS_RFC_8628_KEY);
        if (json.containsKey(USER_CODE)) {
            userCode = json.getString(USER_CODE);
        }
        if (json.containsKey(DEVICE_CODE)) {
            deviceCode = json.getString(DEVICE_CODE);
        }
        if (json.containsKey(VERIFICATION_URI)) {
            deviceFlowCallback = json.getString(VERIFICATION_URI);
        }
        // End RFC 8628 attributes

        dummyAsset = new OA2Asset(null);
        if (json.containsKey(ASSET_KEY)) {
            dummyAsset.fromJSON(json.getJSONObject(ASSET_KEY));
        } else {
            //say("warning -- no stored asset found.");
        }
        say("done!");
    }

    private void showReadHelp() {
        say("read  path");
        sayi("Usage: Reads a saved session from a given file.");
        sayi("See also: write");
    }

    String MESSAGE_SWITCH = "-m";
    String lastUserMessage = null;
    File saveFile = null;

    public void write(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            showWriteHelp();
            return;
        }
        JSONObject jsonObject = new JSONObject();

        if (inputLine.hasArg(MESSAGE_SWITCH)) {
            lastUserMessage = inputLine.getNextArgFor(MESSAGE_SWITCH);
            inputLine.removeSwitchAndValue(MESSAGE_SWITCH);
        }
        if (!isTrivial(lastUserMessage)) {
            jsonObject.put(USER_MESSAGE_KEY, lastUserMessage);
        }

        if (inputLine.getArgCount() == 0) {
            if (saveFile == null) {
                say("sorry, no file specified.");
                return;
            }
        } else {
            saveFile = new File(inputLine.getLastArg());
        }
        jsonObject.put(SYSTEM_MESSAGE_KEY, "OA4MP command line client state stored on " + (new Date()));
        if (grant != null) {
            jsonObject.put(AUTHZ_GRANT_KEY, grant.toJSON());
        }
        if (currentURI != null) {
            jsonObject.put(CURRENT_URI_KEY, currentURI.toString());
        }

        if (dummyAsset != null) {
            jsonObject.put(ASSET_KEY, dummyAsset.toJSON());
        }
        if (saveFile.isDirectory()) {
            say("sorry, but \"" + saveFile.getAbsolutePath() + "\" is a directory");
            return;
        }
        if(!saveFile.isAbsolute()){
            say("Sorry, but " + saveFile.getName() + " needs the path.");
            return;
        }
        if (saveFile.exists()) {
            String r = readline("\"" + saveFile.getAbsolutePath() + "\" exists. Overwrite?[y/n]");
            if (!r.equals("y")) {
                say("aborted. Returning...");
                return;
            }
        }
        jsonObject.put(CONFIG_NAME_KEY, oa2CommandLineClient.getConfigName());
        jsonObject.put(CONFIG_FILE_KEY, oa2CommandLineClient.getConfigFile());

        if (!requestParameters.isEmpty()) {
            JSONObject jj = new JSONObject();
            jj.putAll(requestParameters);
            jsonObject.put(AUTHZ_PARAMETERS_KEY, jj);
        }

        if (!tokenParameters.isEmpty()) {
            JSONObject jj = new JSONObject();
            jj.putAll(tokenParameters);
            jsonObject.put(AUTHZ_PARAMETERS_KEY, jj);
        }

        if (!exchangeParameters.isEmpty()) {
            JSONObject jj = new JSONObject();
            jj.putAll(exchangeParameters);
            jsonObject.put(EXCHANGE_PARAMETERS_KEY, jj);
        }

        if (claims != null && !claims.isEmpty()) {
            jsonObject.put(CLAIMS_KEY, claims);
        }
        if (currentATResponse != null) {
            JSONObject atr = new JSONObject();
            atr.put("access_token", currentATResponse.getAccessToken().toJSON());
            atr.put("refresh_token", currentATResponse.getRefreshToken().toJSON());
            if (currentATResponse.getParameters() != null && !currentATResponse.getParameters().isEmpty()) {
                JSONObject atState = new JSONObject();
                atState.putAll(currentATResponse.getParameters());
                atr.put("parameters", atState);
            }
            jsonObject.put(AT_RESPONSE_KEY, atr);
        }
        // RFC8628 attributes
        jsonObject.put(IS_RFC_8628_KEY, isDeviceFlow);
        if (!isTrivial(deviceCode)) {
            jsonObject.put(DEVICE_CODE, deviceCode);
        }
        if (!isTrivial(userCode)) {
            jsonObject.put(USER_CODE, userCode);
        }
        if (!isTrivial(deviceFlowCallback)) {
            jsonObject.put(VERIFICATION_URI, deviceFlowCallback);
        }
        // End RFC8628 attributes

        FileWriter fileWriter = new FileWriter(saveFile);
        fileWriter.write(jsonObject.toString(1));
        fileWriter.flush();
        fileWriter.close();
        say("done! Saved to \"" + saveFile.getAbsolutePath() + "\".");
    }


    private void showWriteHelp() {
        say("write [" + MESSAGE_SWITCH + " message] path");
        sayi("Usage: Write the current session to a file.");
        sayi("You may read it and resume your session");
        sayi(MESSAGE_SWITCH + " - (optional) a message to include about this session.");
        sayi("Make sure it is double quote delimited");
        sayi("Note that these are serialized to JSON, so you can just go look at one if you like.");
        say("E.g.");
        sayi("write -m \"testing refresh on poloc\" /opt/cilogon-oa2/var/temp/poloc-test.json");
        say("See also: read");
    }


    HashMap<String, String> requestParameters = new HashMap<>();
    HashMap<String, String> tokenParameters = new HashMap<>();
    HashMap<String, String> exchangeParameters = new HashMap<>();

    public static final String REQ_PARAM_SWITCH = "-authz";
    public static final String SHORT_REQ_PARAM_SWITCH = "-a";
    public static final String TOKEN_PARAM_SWITCH = "-token";
    public static final String SHORT_TOKEN_PARAM_SWITCH = "-t";
    public static final String EXCHANGE_PARAM_SWITCH = "-exchange";
    public static final String SHORT_EXCHANGE_PARAM_SWITCH = "-x";

    public void set_param(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            say("set_param " + REQ_PARAM_SWITCH + " | " + TOKEN_PARAM_SWITCH + " | " + EXCHANGE_PARAM_SWITCH + " key value");
            sayi("Usage: Sets an additional request parameter to be send along with the request.");
            sayi(REQ_PARAM_SWITCH + " = parameters for the initial request to the authorization endpoint.");
            sayi(TOKEN_PARAM_SWITCH + " = parameters to send in the token request");
            sayi(EXCHANGE_PARAM_SWITCH + " = parameters for the token exchange request.");
            sayi(shortSwitchBlurb);
            say("See also: get_param, clear_param");
            return;
        }
        boolean setRP = inputLine.hasArg(REQ_PARAM_SWITCH, SHORT_REQ_PARAM_SWITCH);
        boolean setTP = inputLine.hasArg(TOKEN_PARAM_SWITCH, SHORT_TOKEN_PARAM_SWITCH);
        boolean setXP = inputLine.hasArg(EXCHANGE_PARAM_SWITCH, SHORT_EXCHANGE_PARAM_SWITCH);
        inputLine.removeSwitch(REQ_PARAM_SWITCH, SHORT_REQ_PARAM_SWITCH);
        inputLine.removeSwitch(TOKEN_PARAM_SWITCH, SHORT_TOKEN_PARAM_SWITCH);
        inputLine.removeSwitch(EXCHANGE_PARAM_SWITCH, SHORT_EXCHANGE_PARAM_SWITCH);
        if (!(setRP || setTP || setXP)) {
            say("sorry, you must specify the switch for which additional parameters to set");
            return;
        }
        if (inputLine.getArgCount() < 2) {
            say("Sorry, missing argument");
            return;
        }
        if (2 < inputLine.getArgCount()) {
            say("sorry, too many args -- can't determine which is they key and value. Perhaps use double quotes around arguments?");
            return;
        }
        if (setRP) {
            requestParameters.put(inputLine.getArg(1), inputLine.getArg(2));
        }
        if (setTP) {
            tokenParameters.put(inputLine.getArg(1), inputLine.getArg(2));
        }
        if (setXP) {
            exchangeParameters.put(inputLine.getArg(1), inputLine.getArg(2));
        }
    }

    public void get_param(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            say("get_param [" + REQ_PARAM_SWITCH + " | " + TOKEN_PARAM_SWITCH + " | " + EXCHANGE_PARAM_SWITCH + "] key0 key1 key2 ...");
            sayi("Usage: Show what additional parameters have been set.");
            sayi("If no switches are given then both token and authorization additional parameters are shown ");
            sayi("If keys are specified, only those are shown. If no keys are specified, all the given parameters are shown");
            sayi(shortSwitchBlurb);
            say("See also: set_param, clear_param, rm_param");
            return;
        }
        boolean getRP = inputLine.hasArg(REQ_PARAM_SWITCH, SHORT_REQ_PARAM_SWITCH);
        boolean getTP = inputLine.hasArg(TOKEN_PARAM_SWITCH, SHORT_TOKEN_PARAM_SWITCH);
        boolean getXP = inputLine.hasArg(EXCHANGE_PARAM_SWITCH, SHORT_EXCHANGE_PARAM_SWITCH);
        inputLine.removeSwitch(REQ_PARAM_SWITCH, SHORT_REQ_PARAM_SWITCH);
        inputLine.removeSwitch(TOKEN_PARAM_SWITCH, SHORT_TOKEN_PARAM_SWITCH);
        inputLine.removeSwitch(EXCHANGE_PARAM_SWITCH, SHORT_EXCHANGE_PARAM_SWITCH);

        // If nothing is specified, do both
        if (!getRP && !getRP && !getXP) {
            getTP = true;
            getRP = true;
            getXP = true;
        }
        if (getTP) {
            listParams(tokenParameters, inputLine, "tokens");
        }

        if (getRP) {
            listParams(requestParameters, inputLine, "authz");
        }
        if (getXP) {
            listParams(exchangeParameters, inputLine, "exchange");
        }
    }

    private void listParams(Map<String, String> params, InputLine inputLine, String component) {
        if (inputLine.getArgCount() == 0) {
            // show them all
            for (String k : params.keySet()) {
                say(component + ": " + k + "=" + params.get(k));
            }
        } else {
            for (String k : inputLine.getArgs()) {
                if (params.containsKey(k)) {
                    say(component + ": " + k + "=" + params.get(k));
                }
            }
        }
    }

    public void clear_all_params(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            say("clear_all_params " + REQ_PARAM_SWITCH + " | " + TOKEN_PARAM_SWITCH + " | " + EXCHANGE_PARAM_SWITCH);
            say("Usage: Clear all of the additional parameters for the switch.");
            sayi("There is no default to clear all. You must invoke this with both switches or nothing will be done.");
            sayi(shortSwitchBlurb);
            say("See also: set_param, get_param, rm_param");
            return;
        }
        boolean getRP = inputLine.hasArg(REQ_PARAM_SWITCH, SHORT_REQ_PARAM_SWITCH);
        boolean getTP = inputLine.hasArg(TOKEN_PARAM_SWITCH, SHORT_TOKEN_PARAM_SWITCH);
        boolean getXP = inputLine.hasArg(EXCHANGE_PARAM_SWITCH, SHORT_EXCHANGE_PARAM_SWITCH);
        inputLine.removeSwitch(REQ_PARAM_SWITCH, SHORT_REQ_PARAM_SWITCH);
        inputLine.removeSwitch(TOKEN_PARAM_SWITCH, SHORT_TOKEN_PARAM_SWITCH);
        inputLine.removeSwitch(EXCHANGE_PARAM_SWITCH, SHORT_EXCHANGE_PARAM_SWITCH);

        if (!(getTP || getRP || getXP)) {
            say("Sorry, you must specify which set of additional parameters to clear.");
            return;
        }
        if (getTP) {
            tokenParameters = new HashMap<>();
            say("additional token parameters cleared.");
        }
        if (getRP) {
            requestParameters = new HashMap<>();
            say("additional authorization parameters cleared.");
        }
        if (getXP) {
            exchangeParameters = new HashMap<>();
            say("additional exchange parameters cleared.");
        }
    }

    String shortSwitchBlurb = "Short values of switches are allowed: " + SHORT_REQ_PARAM_SWITCH + " | " + SHORT_TOKEN_PARAM_SWITCH + " | " + SHORT_EXCHANGE_PARAM_SWITCH;

    public void rm_param(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            say("rm_param " + REQ_PARAM_SWITCH + " | " + TOKEN_PARAM_SWITCH + " | " + EXCHANGE_PARAM_SWITCH + " key0 key1 ...");
            sayi("Usage: Remove the given key(s) from the set of additional parameters");
            sayi("If none are given, then nothing is done.");
            sayi(shortSwitchBlurb);
            return;
        }
        boolean getRP = inputLine.hasArg(REQ_PARAM_SWITCH, SHORT_REQ_PARAM_SWITCH);
        boolean getTP = inputLine.hasArg(TOKEN_PARAM_SWITCH, SHORT_TOKEN_PARAM_SWITCH);
        boolean getXP = inputLine.hasArg(EXCHANGE_PARAM_SWITCH, SHORT_EXCHANGE_PARAM_SWITCH);
        inputLine.removeSwitch(REQ_PARAM_SWITCH, SHORT_REQ_PARAM_SWITCH);
        inputLine.removeSwitch(TOKEN_PARAM_SWITCH, SHORT_TOKEN_PARAM_SWITCH);
        inputLine.removeSwitch(EXCHANGE_PARAM_SWITCH, SHORT_EXCHANGE_PARAM_SWITCH);

        if (inputLine.getArgCount() == 0) {
            say("No keys found.");
            return;
        }
        int tRemoved = 0;
        int rRemoved = 0;
        int xRemoved = 0;
        for (String k : inputLine.getArgs()) {
            if (getTP) {
                tokenParameters.remove(k);
                tRemoved++;
            }
            if (getRP) {
                requestParameters.remove(k);
                rRemoved++;
            }
            if (getXP) {
                exchangeParameters.remove(k);
                xRemoved++;
            }

        }
        say("removed: " + tRemoved + " token parameters, " + rRemoved + " authz parameters, " + xRemoved + " exchange parameters");
        ;
    }
}
