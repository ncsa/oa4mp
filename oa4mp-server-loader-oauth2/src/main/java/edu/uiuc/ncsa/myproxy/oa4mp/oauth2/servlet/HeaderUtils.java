package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.oauth_2_0.OA2ATException;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.servlet.AbstractServlet;
import org.apache.commons.codec.binary.Base64;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import static edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceConstantKeys.CONSUMER_KEY;

/**
 * Utilities for dealing with getting tokens that may be either sent as parameters
 * or in the authorization header . Note that you should check that if a user sends both, that they match
 * and throw an exception if they do not.
 * <p>Created by Jeff Gaynor<br>
 * on 9/25/17 at  5:33 PM
 */
public class HeaderUtils {
    /**
     * This gets the tokens from the authorization header. There are several types and it is possible to have several
     * values passed in, so this returns an array of string rather than a single value. A downside with passing
     * along several values this way is there is no way to disambiguate them, e.g. a client id from a client secret.
     * If there is no authorization header or there are no tokens of the stated type, the returned value is an
     * empty list.
     *
     * @param request
     * @param type    The type of token, e.g. "Bearer" or "Basic"
     * @return
     */
    public static List<String> getAuthHeader(HttpServletRequest request, String type) {
        Enumeration enumeration = request.getHeaders("authorization");
        ArrayList<String> out = new ArrayList<>();
        while (enumeration.hasMoreElements()) {
            Object obj = enumeration.nextElement();
            if (obj != null) {
                String rawToken = obj.toString();
                if (rawToken == null || 0 == rawToken.length()) {
                    // if there is no bearer token in the authorization header, it must be a parameter in the request.
                    // do nothing. No value
                } else {
                    // This next check is making sure that the type of token requested was sent.
                    //
                    if (rawToken.startsWith(type)) { // note the single space after the type
                        rawToken = rawToken.substring(rawToken.indexOf(" ") + 1);
                        out.add(rawToken);
                    }
                }

            }
        }
        return out;
    }

    public static boolean hasBasicHeader(HttpServletRequest request){
        return getBasicHeader(request)!=null;
    }
    public static String getBasicHeader(HttpServletRequest request) {
        List<String> authHeaders = getAuthHeader(request, "Basic");
        if (authHeaders.isEmpty()) {
            return null;
        }
        return authHeaders.get(0);

    }

    public static String getBearerAuthHeader(HttpServletRequest request) {
        List<String> authHeaders = getAuthHeader(request, "Bearer");
        if (authHeaders.isEmpty()) {
            return null;
        }
        return authHeaders.get(0);

    }

    public static int ID_INDEX = 0;
    public static int SECRET_INDEX = 1;

    // Fix for CIL-430:
    public static String[] getCredentialsFromHeaders(HttpServletRequest request) throws UnsupportedEncodingException {
        String[] out = new String[2];
        // assume the client id and secret are in the headers.
        String header64 = getBasicHeader(request);
        if (header64 == null) {
            return null;
        }
        // semantics are that this is base64.encode(URLEncode(id):URLEncode(secret))
        byte[] headerBytes = Base64.decodeBase64(header64);
        if (headerBytes == null || headerBytes.length == 0) {
            //       DebugUtil.dbg(this, "doIt: no secret, throwing exception.");
            throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT, "Missing secret");
        }
        String header = new String(headerBytes);
        //    DebugUtil.dbg(this, " received authz header of " + header);
        int lastColonIndex = header.lastIndexOf(":");
        if (lastColonIndex == -1) {
            // then this is not in the correct format.
            //      DebugUtil.dbg(this, "doIt: the authorization header is not in the right format, throwing exception.");
            throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT, "the authorization header is not in the right format");

        }

        // semantics are that this is base64.encode(id:secret)

        DebugUtil.dbg(HeaderUtils.class, " received authz header of " + header);
        String id = URLDecoder.decode(header.substring(0,lastColonIndex), "UTF-8");
        out[ID_INDEX] = id;

        String rawSecret = URLDecoder.decode(header.substring(lastColonIndex + 1), "UTF-8");

        out[SECRET_INDEX] = rawSecret;

        return out;
    }

    public static String getSecretFromHeaders(HttpServletRequest request) throws UnsupportedEncodingException {
        return getCredentialsFromHeaders(request)[SECRET_INDEX];
    }
    public static Identifier getIDFromHeaders(HttpServletRequest request) throws UnsupportedEncodingException {
        String[] creds = getCredentialsFromHeaders(request);
        if(creds == null || creds.length == 0){
            return null;
        }
        return BasicIdentifier.newID(creds[ID_INDEX]);

    }

    public static String getATFromParameter(HttpServletRequest request) {
        String rawID = request.getParameter(OA2Constants.ACCESS_TOKEN);
        if (isEmpty(rawID)) {
            return null;
        }
        return rawID;
    }

    public static Identifier getIDFromParameters(HttpServletRequest request) {
        Identifier paramID = null;
        //DebugUtil.dbg(this, "doIt: no header for authentication, looking at parameters.");

        // assume that the secret and id are in the request
        String rawID = request.getParameter(AbstractServlet.CONST(CONSUMER_KEY));
        if (isEmpty(rawID)) {
            return null;
        }
        return BasicIdentifier.newID(rawID);
    }

    protected static boolean isEmpty(String x) {
        return x == null || x.length() == 0;
    }

}
