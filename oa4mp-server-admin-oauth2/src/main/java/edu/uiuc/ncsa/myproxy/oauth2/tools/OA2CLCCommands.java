package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.client.AssetResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStoreUtil;
import edu.uiuc.ncsa.myproxy.oa4mp.server.testing.CLCCommands;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2Asset;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientEnvironment;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2MPService;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.DateUtils;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.delegation.client.request.RTResponse;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;
import edu.uiuc.ncsa.security.delegation.token.Token;
import edu.uiuc.ncsa.security.delegation.token.impl.AuthorizationGrantImpl;
import edu.uiuc.ncsa.security.oauth_2_0.JWTUtil;
import edu.uiuc.ncsa.security.oauth_2_0.UserInfo;
import edu.uiuc.ncsa.security.oauth_2_0.client.ATResponse2;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.JWTUtil2;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import edu.uiuc.ncsa.security.util.pkcs.CertUtil;
import net.sf.json.JSONObject;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.List;
import java.util.*;

import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.ID_TOKEN;
import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.RAW_ID_TOKEN;

/**
 * A command line client. Invoke help as needed, but the basic operation is to create the initial
 * request url using the {@link #geturi(InputLine)} call, paste it in your browser, authenticate
 * (since this is an OIDC client, you must pass through a browser at some point). The call back should
 * fail, so you copy the attempted callback from the service using the {@link #setgrant(InputLine)}
 * call. You can then do whatever you needed (get an access token, get refresh tokens if the server supports it)
 * inspect id tokens and such.
 * <p>Created by Jeff Gaynor<br>
 * on 5/11/16 at  2:57 PM
 */
public class OA2CLCCommands extends CLCCommands {
    public OA2CLCCommands(MyLoggingFacade logger,
                          OA2CommandLineClient oa2CommandLineClient) throws Exception {
        super(logger, (ClientEnvironment) oa2CommandLineClient.getEnvironment());
        this.oa2CommandLineClient = oa2CommandLineClient;
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
        say("seturi | geturi");
        //say("seturi | geturi [" + CLIENT_CFG_NAME_KEY + " config_name]");
        say("Usage: This will create the correct URL. If possible, it will put it in the clipboard.");
        sayi("Create the uri using the  client's configuration");
//        sayi("If the name is given, the configuration is re-read and the named configuration is set to the current one.");
//        sayi("This lets you test several clients in quick succession if needed.");
        sayi("This will put this in to the clipboard if possible.");
        sayi("This URL should be pasted exactly into the location bar.");
        sayi("You must then authenticate. After you authenticate, the");
        sayi("service will attempt a call back to a client endpoint which will");
        sayi("fail (this is the hook that lets us do this manually).");
        sayi("Next Step: You should invoke setgrant with the callback uri from the server.");

    }

    SecureRandom secureRandom = new SecureRandom();

    protected String getRandomString() {
        long ll = secureRandom.nextLong();
        return Long.toHexString(ll);
    }

    String CLIENT_CFG_NAME_KEY = "-name";

    public void seturi(InputLine inputLine) throws Exception {
        geturi(inputLine);
    }

    OA2CommandLineClient oa2CommandLineClient;

    public void load(InputLine inputLine) throws Exception {
        if (!inputLine.hasArgs()) {
            say("config file = " + oa2CommandLineClient.getConfigFile() + ", config name=" + oa2CommandLineClient.getConfigName());
            return;
        }
        oa2CommandLineClient.load(inputLine);
        if (showHelp(inputLine)) {
            return;
        }
        clear(inputLine); // only thing used in clear is --help. If that is present won't get here.
        setCe((ClientEnvironment) oa2CommandLineClient.getEnvironment());
        service = null;
        say("Remember that loading a configuration clears all current state.");
    }

    /**
     * Constructs the URI
     *
     * @param inputLine
     * @throws Exception
     */
    public void geturi(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            getURIHelp();
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
        clear(inputLine);
        Identifier id = AssetStoreUtil.createID();
        OA4MPResponse resp = getService().requestCert(id);
        DebugUtil.trace(this, "client id = " + getCe().getClientId());
        dummyAsset = (OA2Asset) getCe().getAssetStore().get(id.toString());
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        if (clipboard != null) {
            StringSelection data = new StringSelection(resp.getRedirect().toString());
            clipboard.setContents(data, data);
            say("URL copied to clipboard:");
        }
        say(resp.getRedirect().toString());
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

    public void getgrant(InputLine inputLine) throws Exception {
        setgrant(inputLine);
    }

    public void setgrant(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            setGrantHelp();
            return;
        }
        String x = null;
        if (inputLine.size() == 1) {
            // no arg. get it from the clipboard
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            x = (String) clipboard.getData(DataFlavor.stringFlavor);
        } else {

            x = inputLine.getArg(1); // zero-th element is the name of this function. 1st is the actual argument.
        }
        // now we parse this.
        if (!x.startsWith(getCe().getCallback().toString())) {
            say("The callback in the configuration does not match that in the argument you gave");
            return;
        }
        String args = x.substring(x.indexOf("?") + 1); // skip the ? in the substring.
        StringTokenizer st = new StringTokenizer(args, "&");
        while (st.hasMoreTokens()) {
            String current = st.nextToken();
            if (current.startsWith("code=")) {
                URI uri = URI.create(decode(current.substring(5)));
                say("grant=" + uri.toString()); // length of string "code="
                grant = new AuthorizationGrantImpl(uri);
            }
        }
    }

    public OA2Asset getDummyAsset() {
        return dummyAsset;
    }

    public void clear(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            getClearHelp();
            return;
        }
        dummyAsset = null;
        assetResponse = null;
        currentATResponse = null;
        grant = null;
        rawIdToken = null;
        claims = null;

        canGetCert = false;
        canGetGrant = false;
        canGetRT = false;
        canGetAT = false;
    }

    boolean canGetGrant = false;
    boolean canGetAT = false;
    boolean canGetCert = false;
    boolean canGetRT = false;

    protected void getClearHelp() {
        say("clear: reset all internal state and restart. You should do this rather than just starting over");
        say("       as you may run into old state.");
    }

    OA2Asset dummyAsset;

    protected void saveCertHelp() {
        say("savecert filename:");
        say("   This will save the cert (be sure to do a getcert call first so you have one) to the");
        say("   fully qualified filename");
        say("   If there is no cert available, no file will be written, but a message will be printed.");
    }

    /**
     * If the state supports this, it will save the current cert to a file. The complete filename must be supplied,
     * including any path.
     *
     * @param inputLine
     * @throws Exception
     */
    public void savecert(InputLine inputLine) throws Exception {
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
        FileWriter fileWriter = new FileWriter(fileName);
        BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
        bufferedWriter.write(cert + "\n");
        bufferedWriter.flush();
        bufferedWriter.close();
        say("File \"" + fileName + "\" saved successfully.");
    }

    String rawIdToken = null;

    protected void showRawTokenHelp() {
        sayi("showRawToken:");
        say("    This will show the raw id token, i.e., the JWT. ");
        sayi("   If you wish to see the contents of this JWT");
        sayi("   you should probably invoke showClaims instead.");
    }

    public void showrawtoken(InputLine inputLine) throws Exception {
        if (grant == null || showHelp(inputLine)) {
            getATHelp();
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
        say("    This will show the most recent set of claims. You must get an access token");
        sayi("   before this is set.");
        sayi("   You may also see the raw version of this (simply the JWT) by calling showRawToken.");
    }

    protected void showRevokeHelp() {
        say("revoke -at | -rt = revoke either the access token of the refresh token");
    }

    public void revoke(InputLine inputLine) throws Exception {
        if (grant == null || showHelp(inputLine)) {
            showRevokeHelp();
            return;
        }
        boolean revokeAT = inputLine.hasArg("-at");
        boolean revokeRT = inputLine.hasArg("-rt");


    }

    public void getat(InputLine inputLine) throws Exception {
        if (grant == null || showHelp(inputLine)) {
            getATHelp();
            return;
        }
        DebugUtil.trace(this, "Getting AT, grant=" + grant);
        currentATResponse = getOA2S().getAccessToken(getDummyAsset(), grant);
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
        say("getcert");
        say("   This will get the requested cert chain from the server.");
    }

    protected void getUIHelp() {
        say("getuserinfo");
        say("   This will get the user info from the server. You must have already authenticated");
        say("   *and* gotten a valid access token by this point. Just a list of these it printed.");
        say("   What is returned is dependant upon what the server supports.");
        say("   If possible this will be put in to the clipboard for easy access.");
    }

    public void getuserinfo(InputLine inputLine) throws Exception {
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

    public void getcert(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            getCertHelp();
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
        say("getrt ["+ CLAIMS_FLAG  + " | " + NO_VERIFY_JWT + "]:");
        say("   Get a new refresh token. You must have already called getat to have gotten an access token");
        say("   first. This will print out a summary of the expiration time.");
        say("   "+ CLAIMS_FLAG + " = the id token will be printed");
        say("   " + NO_VERIFY_JWT + " = do not verify JWTs against server. Default is to verify.");

    }

    protected JSONObject resolveFromToken(Token token, boolean noVerify) {
        if (noVerify) {
            try {
                String[] components = JWTUtil.decat(token.getToken());
                return JSONObject.fromObject(components[JWTUtil.PAYLOAD_INDEX]);
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

    public void tokens(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            showTokensHelp();
            return;
        }
        printTokens(inputLine.hasArg(NO_VERIFY_JWT));
    }

    private void showTokensHelp() {
        say("tokens [" + NO_VERIFY_JWT + "] - print the current list of tokens");
        say("   " + NO_VERIFY_JWT + " = do not verify JWTs against server. Default is to verify.");
    }

    protected void printTokens(boolean noVerify) {
        // It is possible that the service is down in which case the tokens can't be verified.
        if (dummyAsset.getAccessToken() != null) {
            JSONObject token = null;
            // If the access token is a jwt
            try {
                token = resolveFromToken(getDummyAsset().getAccessToken(), noVerify);
            } catch (Throwable t) {
                say("service is unreachable -- cannot verify token.");
                return;
            }
            if (token == null) {
                say("default access token = " + dummyAsset.getAccessToken().getToken());
            } else {
                sayi("JWT access token:" + token.toString(1));

            }
        }

        if (dummyAsset.getRefreshToken() != null) {
            JSONObject token = null;
            try {
                token = resolveFromToken(getDummyAsset().getRefreshToken(), noVerify);
            } catch (Throwable t) {
                say("service is unreachable -- cannot verify token.");
                return;
            }
            if (token == null) {
                say("default refresh token = " + dummyAsset.getRefreshToken().getToken());
                say("RT expires in = " + dummyAsset.getRefreshToken().getLifetime() + " ms.");
                Date startDate = DateUtils.getDate(dummyAsset.getRefreshToken().getToken());
                startDate.setTime(startDate.getTime() + dummyAsset.getRefreshToken().getLifetime());
                say("   valid until " + startDate);

            } else {
                say("JWT refresh token = " + token.toString(1));
                if (token.containsKey(OA2Claims.EXPIRATION)) {
                    Date d = new Date();
                    d.setTime(token.getLong(OA2Claims.EXPIRATION) * 1000L);
                    //  getDummyAsset().getRefreshToken().setLifetime(d.getTime() - System.currentTimeMillis());
                    say("RT expires in = " + getDummyAsset().getRefreshToken().getLifetime() + " ms.");
                }
            }

        }

    }

    public static final String CLAIMS_FLAG = "-claims";

    public void getrt(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            getRTHelp();
            return;
        }

        RTResponse rtResponse = getOA2S().refresh(dummyAsset.getIdentifier().toString());
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
        say("getat [" + CLAIMS_FLAG + " | " + NO_VERIFY_JWT + "]:");
        say("   Gets the access token and refresh token (if supported on the server) for a given grant. ");
        say("   Your must have already set the grant with the setgrant call.");
        say("   A summary of the refresh token and its expiration is printed, if applicable.");
        say("   "+ CLAIMS_FLAG + " =  he id token will be printed");
        say("   " + NO_VERIFY_JWT + " = do not verify JWTs against server. Default is to verify.");

    }

    protected void setGrantHelp() {
        say("[g|s]etgrant [callback]:");
        say("   The assumption is that you use geturi to get the correct authorization uri and have ");
        say("   logged in. Your browser *should* have a call back to your client.");
        say("   Copy that to the clipboard. If you call this with no argument, then the clipboard is read.");
        say("   Otherwise paste the callback ");
        say("   as the argument to this call. This will return a string with the grant in it. You can use");
        say("   that to get an access token.");
    }

    protected void exchangeHelp() {
        sayi("exchange [-at|-rt]");
        sayi("   This will exchange the current access token (so you need to have gotten that far first)");
        sayi("   for a secure token. The response will contain other information that will be displayed.");
        sayi("   If there is no parameter, the current access token is used for the exchange");
        sayi("   Otherwise you may specify -at to exchange the access token or -rt to exchange using the refresh token.");
    }

    JSONObject sciToken = null;

    public void exchange(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            exchangeHelp();
            return;
        }
        boolean didIt = false;
        if (1 == inputLine.size() || inputLine.hasArg("-at")) {
            didIt = true;
            AccessToken at = getDummyAsset().getAccessToken();
            JSONObject response = getService().exchangeAccessToken(getDummyAsset(), at);
            sciToken = response;

            sayi(response.toString(2));
        }
        if (inputLine.hasArg("-rt")) {
            didIt = true;
            RefreshToken rt = getDummyAsset().getRefreshToken();
            JSONObject response = getService().exchangeRefreshToken(getDummyAsset(), rt);
            sciToken = response;

            sayi(response.toString(2));
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
    protected String AUTHZ_GRANT_KEY = "authz_grant";

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
        if (json.containsKey(AUTHZ_GRANT_KEY)) {

            grant = new AuthorizationGrantImpl(URI.create("a"));
            grant.fromJSON(json.getJSONObject(AUTHZ_GRANT_KEY));
            //grant = new AuthorizationGrantImpl(URI.create(json.getString(AUTHZ_GRANT_KEY)));
            //grant.fromJSON(json.getJSONObject(AUTHZ_GRANT_KEY));
        }

        if (json.containsKey(CONFIG_FILE_KEY)) {
            // make a fake input line for loading the last configuration and run it.
            Vector v = new Vector();
            v.add("load");
            v.add(json.getString(CONFIG_NAME_KEY));
            v.add(json.getString(CONFIG_FILE_KEY));
            InputLine loadLine = new InputLine(v);
            load(loadLine);
        }


        dummyAsset = new OA2Asset(null);
        if (json.containsKey(ASSET_KEY)) {
            dummyAsset.fromJSON(json.getJSONObject(ASSET_KEY));
        } else {
            say("warning -- no stored asset found, so no state was saved.");
        }
        say("done!");
    }

    private void showReadHelp() {
        say("read  path - reads a saved session from a given file.");
        say("See also: write");
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
        if (!StringUtils.isTrivial(lastUserMessage)) {
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
        if (dummyAsset != null) {
            jsonObject.put(ASSET_KEY, dummyAsset.toJSON());
        }
        if (saveFile.isDirectory()) {
            say("sorry, but \"" + saveFile.getAbsolutePath() + "\" is a directory");
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

        if (claims != null && !claims.isEmpty()) {
            jsonObject.put(CLAIMS_KEY, claims);
        }
        FileWriter fileWriter = new FileWriter(saveFile);
        fileWriter.write(jsonObject.toString(1));
        fileWriter.flush();
        fileWriter.close();
        say("done! Saved to \"" + saveFile.getAbsolutePath() + "\".");
    }


    private void showWriteHelp() {
        say("write [" + MESSAGE_SWITCH + " message] path - write the current session state to a file. You may read it and resume your session");
        say("-m - (optional) a message to include about this session. Make sure it is double quote delimited");
        say("Note that these are serialized to JSON.");
        say("E.g.");
        sayi("write -m \"testing refresh on poloc\" /opt/cilogon-oa2/var/temp/poloc-test.json");
        say("See also: read");
    }

    public void grant(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            say("grant - show the current authorization grant if any");
            return;
        }
        if (grant == null) {
            say("(no grant)");
        }
        say(grant.toJSON().toString(1));
    }
}
