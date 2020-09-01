package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.AbstractAccessTokenHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.PayloadHandlerConfigImpl;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunRequest;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse;
import net.sf.json.JSONObject;

import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/26/20 at  4:57 PM
 */
public class WLCGTokenHandler extends AbstractAccessTokenHandler implements WLCGConstants {
    public static String DEFAULT_AUDIENCE = "https://wlcg.cern.ch/jwt/v1/any";

    public WLCGTokenHandler(PayloadHandlerConfigImpl cfg) {
        super(cfg);
    }


    /*
    {
      "wlcg.ver": "1.0",
      "sub": "maltunay@fnal.gov",
      "aud": "https://wlcg.cern.ch/jwt/v1/any",
      "nbf": 1595016911,
      "scope": "storage.read:/store storage.write:/store/data compute.create:/",
      "iss": "https://cilogon.org/",
      "exp": 1595020511,
      "iat": 1595016911,
      "jti": "7abcc281-64f9-48db-a59e-113698dde83a"
    }
     */
/*
    @Override
    public void init() throws Throwable {
        super.init();
        JSONObject wlcg = getAtData();

        wlcg.put(WLCG_VERSION_TAG, WLCG_VERSION_1_0);
        if (transaction.getUserMetaData() != null && transaction.getUserMetaData().containsKey("eppn")) {
            wlcg.put(SUBJECT, transaction.getUserMetaData().getString("eppn"));
        }
        wlcg.put(AUDIENCE, DEFAULT_AUDIENCE);
        // Specific request for expiration is 12 hours
        wlcg.put(EXPIRATION, System.currentTimeMillis() / 1000L + 12L * 60L * 60L); // 12*60*60 = 43200 seconds is 12 hours.

        // canned scopes for the moment because this is the only use case.
        wlcg.put(OA2Constants.SCOPE, "storage.read:/store storage.write:/store/data compute.create:/");
        transaction.setATData(wlcg);
    }
*/

    @Override
    public void addRequestState(ScriptRunRequest req) throws Throwable {

    }

    @Override
    public void handleResponse(ScriptRunResponse resp) throws Throwable {

    }

    @Override
    public void checkClaims() throws Throwable {

    }


    @Override
    public void finish() throws Throwable {

    }

    @Override
    public void saveState() throws Throwable {

    }

    @Override
    public void setAccountingInformation() {
        super.setAccountingInformation();
        JSONObject atData = getAtData();

        atData.put(WLCG_VERSION_TAG, WLCG_VERSION_1_0);
        if (transaction.getUserMetaData() != null && transaction.getUserMetaData().containsKey("eppn")) {
            atData.put(SUBJECT, transaction.getUserMetaData().getString("eppn"));
        }
        atData.put(AUDIENCE, DEFAULT_AUDIENCE);
        // Specific request for expiration is 12 hours
        atData.put(EXPIRATION, System.currentTimeMillis() / 1000L + 12L * 60L * 60L); // 12*60*60 = 43200 seconds is 12 hours.

        // canned scopes for the moment because this is the only use case.
        atData.put(OA2Constants.SCOPE, "storage.read:/store storage.write:/store/data compute.create:/");
        transaction.setATData(atData);
    }

    @Override
    public void refreshAccountingInformation() {

    }
}
