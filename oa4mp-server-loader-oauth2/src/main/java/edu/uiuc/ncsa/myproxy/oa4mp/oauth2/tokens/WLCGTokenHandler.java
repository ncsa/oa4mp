package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.AbstractAccessTokenHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.PayloadHandlerConfigImpl;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.oauth_2_0.OA2ATException;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import net.sf.json.JSONObject;

import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.SCOPE;
import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.AUDIENCE;
import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.SUBJECT;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/26/20 at  4:57 PM
 */
public class WLCGTokenHandler extends AbstractAccessTokenHandler implements WLCGConstants {
    public static String DEFAULT_AUDIENCE = "https://unknown.org";

    public WLCGTokenHandler(PayloadHandlerConfigImpl cfg) {
        super(cfg);
    }

    @Override
    public void setAccountingInformation() {
        super.setAccountingInformation();
        JSONObject atData = getAtData();

        atData.put(WLCG_VERSION_TAG, WLCG_VERSION_1_0);
        if (transaction.getUserMetaData() != null && transaction.getUserMetaData().containsKey("eppn")) {
            atData.put(SUBJECT, transaction.getUserMetaData().getString("eppn"));
        }

        if (getATConfig().getAudience().isEmpty()) {
            atData.put(AUDIENCE, DEFAULT_AUDIENCE);
        } else {
            String a = "";
            for (String x : getATConfig().getAudience()) {
                a = a + " " + x;
            }
            a = a.trim();
            atData.put(AUDIENCE, a);
        }
        transaction.setATData(atData);
    }

    @Override
    public void finish(boolean doTemplates, boolean isQuery) throws Throwable {
        JSONObject atData = getAtData();
        // As per spec., empty scopes means we *may* throw an exception in the generic case
        // and *must* throw one if the capability set is denied.
        if (!atData.containsKey(SCOPE) || StringUtils.isTrivial(atData.getString(SCOPE))) {
            throw new OA2ATException(OA2Errors.ACCESS_DENIED,
                    "No scopes found.",
                    transaction.getRequestState());
        }
        super.finish(doTemplates, isQuery);
    }
}
