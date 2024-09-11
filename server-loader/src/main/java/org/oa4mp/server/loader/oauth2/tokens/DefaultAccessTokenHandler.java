package org.oa4mp.server.loader.oauth2.tokens;

import org.oa4mp.server.loader.oauth2.claims.AbstractAccessTokenHandler;
import org.oa4mp.server.loader.oauth2.claims.PayloadHandlerConfigImpl;
import org.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import org.oa4mp.delegation.common.token.impl.TokenUtils;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;

import java.net.URI;

import static org.oa4mp.delegation.server.server.claims.OA2Claims.JWT_ID;

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
    public AccessTokenImpl getSignedPayload(JSONWebKey key) {
        if (!getPayload().containsKey(JWT_ID)) {
            // There is something wrong. This is required.
            throw new IllegalStateException("Error: no JTI. Cannot create access token");
        }
        AccessTokenImpl at = new AccessTokenImpl(URI.create(TokenUtils.b32EncodeToken(getPayload().getString(JWT_ID))));
        return at;
    }

/*    @Override
    public void setAccountingInformation() {
        long lifetime = ClientUtils.computeATLifetime(transaction, oa2se);
        OA2ServiceTransaction transaction = getPhCfg().getTransaction();
        if (0 < getATConfig().getLifetime()) {
            transaction.setAccessTokenLifetime(System.currentTimeMillis() + getATConfig().getLifetime());
        } else {
            transaction.setAccessTokenLifetime(System.currentTimeMillis() + OA2ConfigurationLoader.ACCESS_TOKEN_LIFETIME_DEFAULT);
        }
        super.setAccountingInformation();
    }*/
}
