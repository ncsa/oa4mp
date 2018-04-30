package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.EnvServlet;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.oauth_2_0.JWTUtil;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.SQLException;
import java.util.StringTokenizer;

/**
 * A servlet to allow for certain utilities, such as checking if claims contain a given value.
 * <p>Created by Jeff Gaynor<br>
 * on 1/4/18 at  11:19 AM
 */
public class OA2UtilServlet extends EnvServlet {
    public static String ACTION_KEY = "action";
    public static String ACTION_CHECK_CLAIM = "check_claim";
    public static String TOKEN_KEY = "token";
    public static String CLAIM_NAME_KEY = "claim_name";
    public static String CLAIM_VALUE_KEY = "claim_value";

    @Override
    protected void doIt(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable {
        OA2SE oa2se = (OA2SE) getEnvironment();
        if (!oa2se.isUtilServletEnabled()) {
            return;
        }
        String action = getParameter(httpServletRequest, httpServletResponse, ACTION_KEY);

        if (action == null) {
            return;
        }

        if (!action.equals(ACTION_CHECK_CLAIM)) {
            spitOutMessage(httpServletResponse, CODE_ERROR, "unknown action of \"" + action + "\" requested from util servlet");
            return;
        }
        String claimName = getParameter(httpServletRequest, httpServletResponse, CLAIM_NAME_KEY);
        if (claimName == null) {
            return;
        }
        String claimValue = getParameter(httpServletRequest, httpServletResponse, CLAIM_VALUE_KEY);
        if (claimValue == null) {
            return;
        }

        String token = getParameter(httpServletRequest, httpServletResponse, TOKEN_KEY);
        if (token == null) {
            return;
        }

        JSONObject json = null;
        // so we have everything and are ready to rock.
        try {
            json = JWTUtil.verifyAndReadJWT(token, oa2se.getJsonWebKeys());
        } catch (Throwable t) {
            spitOutMessage(httpServletResponse, CODE_ERROR, "Invalid token. Message=\"" + t.getMessage() + "\"");
            return;

        }

        if (!json.containsKey(claimName)) {
            spitOutMessage(httpServletResponse, CODE_ERROR, "claim named \"" + claimName + "\" not found.");
            return;
        }
        // simple case is its just a string
        Object rawClaims = json.get(claimName);
        if (rawClaims instanceof JSONArray) {
            JSONArray array = (JSONArray) rawClaims;
            for (int i = 0; i < array.size(); i++) {
                String nextString = array.getString(i);
                // first cut, parse by , as delimiter.
                StringTokenizer st = new StringTokenizer(nextString, ",", false);
                while(st.hasMoreTokens()){
                    String x = st.nextToken();
                    if(claimValue.equals(x)){
                        spitOutMessage(httpServletResponse, CODE_OK, null);
                    }
                }
            }
            spitOutMessage(httpServletResponse, CODE_NO, null);
            return;
        }

        // Every other case (including JSONObject, which we don't know how to parse in general)
        String claim = rawClaims.toString();
        if (-1 < claim.indexOf(claimValue)) {
            spitOutMessage(httpServletResponse, CODE_OK, null);
        } else {
            spitOutMessage(httpServletResponse, CODE_NO, null);

        }
        return;

    }

    public static final int CODE_OK = 1;
    public static String RESPONSE_OK = "ok";
    public static String RESPONSE_FAIL = "no";
    public static String RESPONSE_ERROR = "error";
    public static final int CODE_NO = 0;
    public static final int CODE_ERROR = -1;
    public static String STATUS_KEY = "status";
    public static String MESSAGE_KEY = "message";
    /**
     * Prints a message to info (unless the message is null) and the returnedMessage is written to the response and closed.
     * Do not call the response's Writer after calling this message.
     *
     * @param resp
     * @param code
     * @param infoMessage
     * @throws Throwable
     */
    protected void spitOutMessage(HttpServletResponse resp, int code, String infoMessage) throws Throwable {
        PrintWriter pw = resp.getWriter();
        JSONObject json = new JSONObject();
        if (infoMessage != null) {
            info(infoMessage);
        }

        switch(code){
            case CODE_OK:
                json.put(STATUS_KEY,RESPONSE_OK);
                resp.setStatus(HttpStatus.SC_OK);
                break;
            case CODE_NO:
                json.put(STATUS_KEY,RESPONSE_FAIL);
                resp.setStatus(HttpStatus.SC_OK);
                break;
            case CODE_ERROR:
                json.put(STATUS_KEY,RESPONSE_ERROR);
                json.put(MESSAGE_KEY,infoMessage);
                resp.setStatus(HttpStatus.SC_NOT_FOUND);
                break;
            default:
                throw new NFWException("Internal error: unknown action requested");
        }

        pw.println(json.toString());
        pw.flush();
        pw.close();
    }

    protected String getParameter(HttpServletRequest request, HttpServletResponse response, String paramName) throws Throwable {
        String p = getFirstParameterValue(request, paramName);
        if (p == null || p.isEmpty()) {
            spitOutMessage(response,
                    CODE_ERROR,
                    "warning. Util servlet received a request that was missing the \"" + paramName + "\". Request rejected");

            return null;
        }
        return p;
    }


    @Override
    public void storeUpdates() throws IOException, SQLException {
        // not implmeneted.
    }
}
