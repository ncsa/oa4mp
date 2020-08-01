package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.client.AssetResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientXMLTags;
import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStoreUtil;
import edu.uiuc.ncsa.myproxy.oa4mp.server.testing.CLCCommands;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2Asset;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientEnvironment;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientLoader;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2MPService;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.DateUtils;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.client.request.RTResponse;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;
import edu.uiuc.ncsa.security.delegation.token.impl.AuthorizationGrantImpl;
import edu.uiuc.ncsa.security.oauth_2_0.JWTUtil;
import edu.uiuc.ncsa.security.oauth_2_0.UserInfo;
import edu.uiuc.ncsa.security.oauth_2_0.client.ATResponse2;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.JWTUtil2;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.configuration.ConfigUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import edu.uiuc.ncsa.security.util.pkcs.CertUtil;
import net.sf.json.JSONObject;
import org.apache.commons.configuration.tree.ConfigurationNode;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.SecureRandom;
import java.util.Date;
import java.util.HashMap;
import java.util.StringTokenizer;

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
    public OA2CLCCommands(MyLoggingFacade logger, ClientEnvironment ce) {
        super(logger, ce);
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
        say("seturi | geturi [" + CLIENT_CFG_NAME_KEY + " config_name]");
        say("Usage: This will create the correct URL. If possible, it will put it in the clipboard.");
        sayi("if no argument is given, then the default name for the client's configuration is used");
        sayi("If the name is given, the configuration is re-read and the named configuration is set to the current one.");
        sayi("This lets you test several clients in quick succession if needed.");
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
        if (inputLine.hasArg(CLIENT_CFG_NAME_KEY)) {
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
        }
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

    AuthorizationGrant grant;

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

    public void showclaims(InputLine inputLine) throws Exception {
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
        printTokens();

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

    protected void getRTHelp() {
        say("getrt [-claims]:");
        say("   Get a new refresh token. You must have already called getat to have gotten an access token");
        say("   first. This will print out a summary of the expiration time.");
        say("   If the " + CLAIMS_FLAG + " flag is supplied, the id token will be printed");
    }

    protected void printTokens() {
        if (dummyAsset.getAccessToken() != null) {
            // If the access token is a jwt
            AccessToken accessToken = getDummyAsset().getAccessToken();
            JSONWebKeys keys = JWTUtil2.getJsonWebKeys(getService().getServiceClient(), ((OA2ClientEnvironment) getService().getEnvironment()).getWellKnownURI());
              boolean isJWT = false;
            try {
                JSONObject json = JWTUtil.verifyAndReadJWT(accessToken.getToken(), keys);
                sayi("Access token is a JWT:");
                say(json.toString(1));
                isJWT = true;
            } catch (Throwable t) {
                // do nothing.
            }
            say((isJWT?"raw ":"") + "access token = " + dummyAsset.getAccessToken().getToken());
        }
        if (dummyAsset.getRefreshToken() != null) {
            say("refresh token = " + dummyAsset.getRefreshToken().getToken());
            say("RT expires in = " + dummyAsset.getRefreshToken().getExpiresIn() + " ms.");
            Date startDate = DateUtils.getDate(dummyAsset.getRefreshToken().getToken());
            startDate.setTime(startDate.getTime() + dummyAsset.getRefreshToken().getExpiresIn());
            say("   expires at " + startDate);
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
        printTokens();
    }


    protected void getATHelp() {
        say("getat [-claims]:");
        say("   Gets the access token and refresh token (if supported on the server) for a given grant. ");
        say("   Your must have already set the grant with the setgrant call.");
        say("   A summary of the refresh token and its expiration is printed, if applicable.");
        say("   If the -" + CLAIMS_FLAG + " flag is supplied, the id token will be printed");

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
}
