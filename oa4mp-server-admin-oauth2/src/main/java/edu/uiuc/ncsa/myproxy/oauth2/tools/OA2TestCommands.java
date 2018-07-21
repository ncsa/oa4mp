package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.client.AssetResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStoreUtil;
import edu.uiuc.ncsa.myproxy.oa4mp.server.testing.TestCommands;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2Asset;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2MPService;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.DateUtils;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.client.request.RTResponse;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.delegation.token.impl.AuthorizationGrantImpl;
import edu.uiuc.ncsa.security.oauth_2_0.UserInfo;
import edu.uiuc.ncsa.security.oauth_2_0.client.ATResponse2;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.pkcs.CertUtil;
import net.sf.json.JSONObject;

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
 * <p>Created by Jeff Gaynor<br>
 * on 5/11/16 at  2:57 PM
 */
public class OA2TestCommands extends TestCommands {
    public OA2TestCommands(MyLoggingFacade logger, ClientEnvironment ce) {
        super(logger, ce);
    }

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
        say("Usage: This will create the correct URL to pass to your browser.");
        say("       This URL should be pasted exactly into the location bar.");
        say("       You must then authenticate. After you authenticate, the");
        say("       service will attempt a call back to a client endpoint which will");
        say("       fail (this is the hook that lets us do this manually).");
        say("       Next Step: You should invoke setgrant with the callback uri from the server.");

    }

    SecureRandom secureRandom = new SecureRandom();

    protected String getRandomString() {
        long ll = secureRandom.nextLong();
        return Long.toHexString(ll);
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
        Identifier id = AssetStoreUtil.createID();
        OA4MPResponse resp = getService().requestCert(id);
        dummyAsset = (OA2Asset) getCe().getAssetStore().get(id.toString());
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

    public void setgrant(InputLine inputLine) throws Exception {
        if (inputLine.size() != 2 || showHelp(inputLine)) {
            setGrantHelp();
            return;
        }
        String x = inputLine.getArg(1); // zero-th element is the name of this function. 1st is the actual argument.
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
        say("savecert filename");
        say("This will save the cert (be sure to do a getcert call first so you have one) to the");
        say("fully qualified filename");
        say("If there is no cert available, no file will be written, but a message will be printed.");
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
        sayi("showRawToken - This will show the raw id token, i.e., the JWT. ");
        sayi("               If you wish to see the contents of this JWT");
        sayi("               you should probably invoke showClaims instead.");
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
        sayi("showClaims - This will show the most recent set of claims. You must get an access token");
        sayi("             before this is set.");
        sayi("             You may also see the raw version of this (simply the JWT) by calling showRawToken.");
    }

    public void getat(InputLine inputLine) throws Exception {
       /* if(!canGetAT){
            say("Sorry, but you have not gotten a grant yet here, so you cannot get an access token.");
        }*/
        if (grant == null || showHelp(inputLine)) {
            getATHelp();
            return;
        }

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
        say("getcert: This will get the requested cert chain from the server.");
    }

    protected void getUIHelp() {
        say("getuserinfo: This will get the user info from the server. You must have already authenticated");
        say("             *and* gotten a valid access token by this point. Just a list of these it printed.");
        say("             What is returned is dependant upon what the server supports.");
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
        say("       Get a new refresh token. You must have already called getat to have gotten an access token");
        say("       first. This will print out a summary of the expiration time.");
        say("       If the " + CLAIMS_FLAG + " flag is supplied, the id token will be printed");
    }

    protected void printTokens() {
        if (dummyAsset.getAccessToken() != null) {
            say(" access token = " + dummyAsset.getAccessToken().getToken());
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
        say("       Gets the access token and refresh token (if supported on the server) for a given grant. ");
        say("       Your argument is the output from the setgrant call here.");
        say("       A summary of the refresh token and its expiration is printed, if applicable.");
        say("       If the -" + CLAIMS_FLAG + " flag is supplied, the id token will be printed");

    }

    protected void setGrantHelp() {
        say("setgrant: The assumption is that you use geturi to get the correct authorization uri and have ");
        say("          logged in. Your browser *should* have a call back to your client. Cut and paste that");
        say("          as the argument to this call. This will return a string with the grant in it. You can use");
        say("          that to get an access token.");
    }
}
