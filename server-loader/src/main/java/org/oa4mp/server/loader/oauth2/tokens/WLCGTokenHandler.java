package org.oa4mp.server.loader.oauth2.tokens;

import org.oa4mp.server.loader.oauth2.claims.AbstractAccessTokenHandler;
import org.oa4mp.server.loader.oauth2.claims.PayloadHandlerConfigImpl;
import org.oa4mp.server.api.storage.servlet.MyProxyDelegationServlet;
import org.oa4mp.delegation.server.OA2ATException;
import org.oa4mp.delegation.server.OA2Errors;
import org.oa4mp.delegation.server.server.RFC9068Constants;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import net.sf.json.JSONObject;

import static org.oa4mp.delegation.server.OA2Constants.SCOPE;
import static org.oa4mp.delegation.server.server.claims.OA2Claims.AUDIENCE;
import static org.oa4mp.delegation.server.server.claims.OA2Claims.SUBJECT;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/26/20 at  4:57 PM
 */
public class WLCGTokenHandler extends AbstractAccessTokenHandler implements WLCGConstants {
    public static String DEFAULT_AUDIENCE = "https://unknown.org";

    public WLCGTokenHandler(PayloadHandlerConfigImpl cfg) {
        super(cfg);
        MyProxyDelegationServlet.createDebugger(cfg.getTransaction().getClient()).trace(this, "Created WLCG handler with transaction " + cfg.getTransaction().summary());
    }

    @Override
    public void setAccountingInformation() {
        super.setAccountingInformation();
        JSONObject atData = getPayload();
        // NOTE: wlcg.groups are not processed here since the source for them is not
        // canonical, i.e., they may come from any of a number of sources so there is
        // just no way to know a priori what to use. 
        // See P. 17 https://indico.cern.ch/event/769180/contributions/3563095/attachments/1908176/3152124/WLCG_Common_JWT_Profiles.pdf
        // These are therefore normally done in QDL.
        atData.put(WLCG_VERSION_TAG, WLCG_VERSION_1_0);
        // We set the subject to the EPPN if it is present.
        if (transaction.getUserMetaData() != null && transaction.getUserMetaData().containsKey("eppn")) {
            atData.put(SUBJECT, transaction.getUserMetaData().getString("eppn"));
        }
        // WLCG also supports a few constants from the 9068 spec.
        if (getUserMetaData().containsKey(RFC9068Constants.AUTHENTICATION_CLASS_REFERENCE)) {
            atData.put(RFC9068Constants.AUTHENTICATION_CLASS_REFERENCE, getUserMetaData().get(RFC9068Constants.AUTHENTICATION_CLASS_REFERENCE));
        }
        atData.put(RFC9068Constants.AUTHENTICATION_TIME, transaction.getAuthTime().getTime() / 1000);
        // Some IDPS might also include this. Send it along if present.
        if (getUserMetaData().containsKey(EDUPERSON_ASSURANCE)) {
            atData.put(EDUPERSON_ASSURANCE, getUserMetaData().get(EDUPERSON_ASSURANCE));
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
        JSONObject atData = getPayload();
        // As per spec., empty scopes means we *may* throw an exception in the generic case
        // and *must* throw one if the capability set is denied.
        super.finish(doTemplates, isQuery);
        if (!atData.containsKey(SCOPE) || StringUtils.isTrivial(atData.getString(SCOPE))) {
            throw new OA2ATException(OA2Errors.ACCESS_DENIED,
                    "No scopes found.",
                    transaction.getRequestState(),
                    transaction.getClient());
        }
    }
}
