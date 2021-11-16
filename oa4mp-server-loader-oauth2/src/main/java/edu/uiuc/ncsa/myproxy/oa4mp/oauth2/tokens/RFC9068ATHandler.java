package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.AbstractAccessTokenHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.PayloadHandlerConfigImpl;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.oauth_2_0.server.RFC8693Constants;
import edu.uiuc.ncsa.security.oauth_2_0.server.RFC9068Constants;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import net.sf.json.JSONObject;

import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.SUBJECT;

/**
 * Handler for access tokens as per <a href="https://www.rfc-editor.org/rfc/rfc9068">RFC 9068</a>.
 * <p>Created by Jeff Gaynor<br>
 * on 11/16/21 at  8:10 AM
 */
public class RFC9068ATHandler extends AbstractAccessTokenHandler implements RFC9068Constants {
    public RFC9068ATHandler(PayloadHandlerConfigImpl payloadHandlerConfig) {
        super(payloadHandlerConfig);
    }


    @Override
    public void init() throws Throwable {
        super.init();
        JSONObject sciTokens = getAtData();
        sciTokens.put(SUBJECT, transaction.getUsername());
        sciTokens.put(RFC8693Constants.CLIENT_ID, transaction.getOA2Client().getIdentifierString());
    }

    @Override
    public AccessToken getSignedAT(JSONWebKey key) {
        return getSignedAT(key, HEADER_TYPE);
    }
}
