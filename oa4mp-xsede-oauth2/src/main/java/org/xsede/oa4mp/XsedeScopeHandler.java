package org.xsede.oa4mp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import javax.ws.rs.core.HttpHeaders;

import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

import javax.json.Json;
import javax.json.JsonReader;
import javax.json.JsonObject;

import org.apache.http.util.EntityUtils;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.BasicScopeHandler;
import edu.uiuc.ncsa.security.oauth_2_0.UserInfo;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.oauth_2_0.server.UnsupportedScopeException;
import static edu.uiuc.ncsa.security.oauth_2_0.OA2Scopes.SCOPE_PROFILE;
import static edu.uiuc.ncsa.security.oauth_2_0.OA2Scopes.SCOPE_EMAIL;

import java.util.logging.Logger;

/**
 * XsedeScopeHandler
 *
 */
public class XsedeScopeHandler extends BasicScopeHandler { 
    public static final String SCOPE_XSEDE = "xsede";

    private String OA4MP_USER = "username";
    private String OA4MP_PASSWORD = "password";
    private String OA4MP_API_KEY = "api-key";
    private String OA4MP_API_HASH = "hash";
    private String OA4MP_API_URL = "url";
    private String OA4MP_API_RESOURCE = "resource";
    private String authToken;
    MyLoggingFacade myLogger;

    public XsedeScopeHandler(String Username, String Password, MyLoggingFacade logger) {
        super();
        OA4MP_USER = Username;
       	OA4MP_PASSWORD = Password;
        OA4MP_API_KEY = null;
        OA4MP_API_HASH = null;
        myLogger = logger;
        resetAuthToken();
    }

    public XsedeScopeHandler(MyLoggingFacade logger, String ApiKey, String ApiHash, String ApiURL, String ApiResource) {
        super();
        OA4MP_API_KEY = ApiKey;
       	OA4MP_API_HASH = ApiHash;
        OA4MP_API_URL = ApiURL;
        OA4MP_API_RESOURCE = ApiResource;
        OA4MP_USER = null;
       	OA4MP_PASSWORD = null;
        myLogger = logger;
    }

    private void resetAuthToken() {

        myLogger.debug("Resetting XCDB authtoken");
        String auth = OA4MP_USER + ":" + OA4MP_PASSWORD;
        byte[] encodedAuth = Base64.encodeBase64(auth.getBytes(Charset.forName("ISO-8859-1")));
        String authHeader = "Basic " + new String(encodedAuth);

        DefaultHttpClient httpClient = new DefaultHttpClient();
        HttpPost postRequest = new HttpPost(
            "https://api.xsede.org/tokens/v1");
        postRequest.addHeader("accept", "application/json");
        postRequest.addHeader("Cache-Control", "no-cache");

        postRequest.setHeader(HttpHeaders.AUTHORIZATION, authHeader);
        try {
            HttpResponse response = httpClient.execute(postRequest);

            if (response.getStatusLine().getStatusCode() != 200) {
                myLogger.error("Unable to retrieve authentication token from XDCDB: HTTP error: " +
                    response.getStatusLine().toString());
                throw new RuntimeException("Unable to retrieve authentication token; HTTP Error");
            }

            JsonReader rdr = Json.createReader(response.getEntity().getContent());
            JsonObject obj = rdr.readObject();
            authToken = obj.getJsonArray("result".toString()).getJsonObject(0).getString("token".toString());
        } catch (IOException E) {
            myLogger.error("IOException while trying to retrieve authentication token from XDCDB:"
                                          + E.toString());
            throw new RuntimeException("Unable to retrieve authentication token; IOException", E);
        }
    }

    private JsonObject getUserInfo(String subject) {
        JsonObject profile;
        if (OA4MP_API_KEY != null)
            profile = getUserInfo2(subject);
        else {
            profile = getUserInfo1(subject);
            if (profile == null) {
                myLogger.info("Resetting authtoken used to retrieve userinfo from XDCDB");
                resetAuthToken();
                profile = getUserInfo1(subject);
            }
        }

        if (profile == null) {
                myLogger.error("Unable to retrieve userinfo from XDCDB");
                throw new RuntimeException("Unable to retrieve userinfo");
        }

        return profile;
    }

    private JsonObject getUserInfo2(String subject) {
        try {

            DefaultHttpClient httpClient = new DefaultHttpClient();
            HttpGet getRequest = new HttpGet(OA4MP_API_URL + "/" + subject);
            getRequest.addHeader("accept", "application/json");
            getRequest.addHeader("Cache-Control", "no-cache");
            getRequest.addHeader("XA-AGENT", "userinfo");
            getRequest.addHeader("XA-RESOURCE", OA4MP_API_RESOURCE);
            getRequest.addHeader("XA-API-KEY", OA4MP_API_KEY);

            HttpResponse response = httpClient.execute(getRequest);

            if (response.getStatusLine().getStatusCode() != 200) {
                myLogger.info("Unable to retrieve userinfo from XDCDB: HTTP error: " +
                    response.getStatusLine().toString());
                return null;
            }

            JsonReader rdr = Json.createReader(response.getEntity().getContent());
            JsonObject obj = rdr.readObject();

            myLogger.debug("API SERVER RESPONSE:");
            myLogger.debug(obj.toString());
            return obj.getJsonObject("result".toString());
        } catch (IOException E) {
            myLogger.error("IOException while trying to retrieve userinfo from XDCDB:"
                                          + E.toString());
            throw new RuntimeException("Unable to retrieve userinfo; IOException", E);
        }
    }

    private JsonObject getUserInfo1(String subject) {
        try {
            // Get user record for "subject" using "token" for password.
            String auth = OA4MP_USER + ":" + authToken;
            byte[] encodedAuth = Base64.encodeBase64(auth.getBytes(Charset.forName("ISO-8859-1")));
            String authHeader = "Basic " + new String(encodedAuth);

            DefaultHttpClient httpClient = new DefaultHttpClient();
            HttpGet getRequest = new HttpGet("https://api.xsede.org/profile/v1" + "/" + subject);
            getRequest.addHeader("accept", "application/json");
            getRequest.addHeader("Cache-Control", "no-cache");

            getRequest.setHeader(HttpHeaders.AUTHORIZATION, authHeader);

            HttpResponse response = httpClient.execute(getRequest);

            if (response.getStatusLine().getStatusCode() != 200) {
                myLogger.info("Unable to retrieve userinfo from XDCDB: HTTP error: " +
                    response.getStatusLine().toString());
                return null;
            }

            JsonReader rdr = Json.createReader(response.getEntity().getContent());
            JsonObject obj = rdr.readObject();
            return obj.getJsonArray("result".toString()).getJsonObject(0);
        } catch (IOException E) {
            myLogger.error("IOException while trying to retrieve userinfo from XDCDB:"
                                          + E.toString());
            throw new RuntimeException("Unable to retrieve userinfo; IOException", E);
        }
    }

    @Override
    public UserInfo process(UserInfo userInfo, ServiceTransaction transaction) throws UnsupportedScopeException
    {
        OA2ServiceTransaction t = (OA2ServiceTransaction) transaction;

        myLogger.info("In XSEDE scope handler9: " + getScopes());

        String subject = t.getUsername();

        if (subject == null) {
            myLogger.debug("No subject available in transaction");
            return userInfo; // nothing can be done without subject info
        }

        // See if userInfo already has the requisite info
        myLogger.debug("Profile:"+t.getScopes().contains(SCOPE_PROFILE)+":"+
            userInfo.getGiven_name()+":"+userInfo.getMiddle_name()+":"+userInfo.getFamily_name());
        myLogger.debug("EMAIL:"+userInfo.getEmail());
        myLogger.debug("XSEDE:"+userInfo.getString("xsedeHomeOrganization".toString()));

        if ((!t.getScopes().contains(SCOPE_PROFILE) ||
                 (userInfo.getGiven_name() != null && userInfo.getMiddle_name() != null &&
                  userInfo.getFamily_name() != null))
            &&
            (!t.getScopes().contains(SCOPE_EMAIL) || (userInfo.getEmail() != null))
            &&
            (!t.getScopes().contains(SCOPE_XSEDE) || (userInfo.getString("xsedeHomeOrganization".toString()) != null))) {
            myLogger.info("Info for all claims in requested scopes already " +
                "available in userInfo; skipping call to XDCDB");
            return userInfo;
        }

        // One or more requisite info missing; retrieve from XCDB and set
        JsonObject profile = getUserInfo(subject);
        String firstName = profile.isNull("first_name".toString())?"".toString():
                               profile.getString("first_name".toString());
        String middleName = profile.isNull("middle_name".toString())?"".toString():
				profile.getString("middle_name".toString());
        String lastName = profile.isNull("last_name".toString())?"".toString():
                              profile.getString("last_name".toString());
        String email = profile.isNull("email".toString())?"".toString():
                              profile.getString("email".toString());
        String organization = profile.isNull("organization".toString())?"".toString():
                                  profile.getString("organization".toString());

        if (t.getScopes().contains(SCOPE_PROFILE)) {
            myLogger.info("Processing profile scope in XSEDE handler");
            userInfo.setGiven_name(firstName);
            userInfo.setMiddle_name(middleName);
            userInfo.setFamily_name(lastName);
        }

        if (t.getScopes().contains(SCOPE_EMAIL)) {
            myLogger.info("Processing email scope in XSEDE handler");
            userInfo.setEmail(email);
        }

        if (t.getScopes().contains(SCOPE_XSEDE)) {
            myLogger.info("Processing xsede scope in XSEDE handler");
            userInfo.put("xsedeHomeOrganization".toString(), organization);
        }

        return userInfo;
    }
}
