package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.transactions.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.AbstractAccessTokenHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.PayloadHandlerConfigImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.delegation.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.security.delegation.token.impl.TokenUtils;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import net.sf.json.JSONObject;

import java.net.URI;

import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.JWT_ID;

/**
 * For an opaque token. This is <b>NOT</b> a JWT, but does allow for setting a few parameters, viz.,
 * the lifetime and QDL can be specified.
 * <p>Created by Jeff Gaynor<br>
 * on 1/10/22 at  11:13 AM
 */
public class DefaultAccessTokenHandler extends AbstractAccessTokenHandler {
    public DefaultAccessTokenHandler(PayloadHandlerConfigImpl payloadHandlerConfig) {
        super(payloadHandlerConfig);
    }

    @Override
    public AccessToken getSignedAT(JSONWebKey key) {
        if (!getAtData().containsKey(JWT_ID)) {
            // There is something wrong. This is required.
            throw new IllegalStateException("Error: no JTI. Cannot create access token");
        }
        AccessTokenImpl at = new AccessTokenImpl(URI.create(TokenUtils.b32EncodeToken(getAtData().getString(JWT_ID))));
        return at;
    }

    @Override
    public void setAccountingInformation() {
        JSONObject atData = getAtData();
        // Could try to create a token with a custom lifetime, but that would involve   re-creating the token
        // and applying all the server logic to make sure the lifetime is right.
/*        OA2TokenForge oa2TokenForge = null;
        ATRequest atRequest = new ATRequest(null, getPhCfg().getTransaction());

        oa2TokenForge.createToken(atRequest);*/
        OA2ServiceTransaction transaction = getPhCfg().getTransaction();
        if (0 < getATConfig().getLifetime()) {
            transaction.setAccessTokenLifetime(System.currentTimeMillis() + getATConfig().getLifetime());
        } else {
            transaction.setAccessTokenLifetime(System.currentTimeMillis() + OA2ConfigurationLoader.ACCESS_TOKEN_LIFETIME_DEFAULT);
        }
        super.setAccountingInformation();
    }
}
