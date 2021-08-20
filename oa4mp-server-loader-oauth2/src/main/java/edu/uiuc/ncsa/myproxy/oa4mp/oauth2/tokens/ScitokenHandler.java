package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.AbstractAccessTokenHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.PayloadHandlerConfigImpl;
import net.sf.json.JSONObject;

import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.SUBJECT;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/21/20 at  4:55 PM
 */
public class ScitokenHandler extends AbstractAccessTokenHandler {
    public ScitokenHandler(PayloadHandlerConfigImpl payloadHandlerConfig) {
        super(payloadHandlerConfig);
    }

//    String ST_SCOPE = "scope";
    String ST_CLIENT_IDENTIFIER = "cid";
    String VERSION_2_0 = "scitoken:2.0";
    String ST_VERSION_CLAIM = "ver";


    public String getUsernameClaimKey() {
        return ((SciTokenConfig)getPhCfg().getPayloadConfig()).getUsernameClaimKey();
    }

    /**
     * NOTE that the SciTokens spec. changed substantially form version 1.0 to 2.0. we  do
     * not support 1.0.
     *
     * @return
     */
    protected String getVersion() {
        return VERSION_2_0;
    }

    @Override
    public void init() throws Throwable {
        super.init();
        JSONObject sciTokens = getAtData();

        // subject is optional
        sciTokens.put(SUBJECT, transaction.getUsername());
        sciTokens.put(ST_CLIENT_IDENTIFIER, transaction.getOA2Client().getIdentifierString());
        sciTokens.put(ST_VERSION_CLAIM, getVersion()); // make sure set for inter-operability with others
    }
}
