package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.AbstractAccessTokenHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.PayloadHandlerConfigImpl;
import net.sf.json.JSONObject;

import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.*;

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

}
