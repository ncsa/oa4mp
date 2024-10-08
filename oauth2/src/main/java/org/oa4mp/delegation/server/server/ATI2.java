package org.oa4mp.delegation.server.server;

import org.oa4mp.delegation.common.token.TokenForge;
import org.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import org.oa4mp.delegation.common.token.impl.RefreshTokenImpl;
import org.oa4mp.delegation.server.OA2TokenForge;
import org.oa4mp.delegation.server.OA2Utilities;
import org.oa4mp.delegation.server.issuers.ATIssuer;
import org.oa4mp.delegation.server.issuers.AbstractIssuer;
import org.oa4mp.delegation.server.request.ATRequest;
import org.oa4mp.delegation.server.request.ATResponse;

import java.net.URI;
import java.util.Map;

/**
 * Access token issuer class for OAuth2.  Creates and issues
 * access tokens
 * <p>Created by Jeff Gaynor<br>
 * on 6/4/13 at  5:05 PM
 */
public class ATI2 extends AbstractIssuer implements ATIssuer {
    boolean isOIDC = true;
    /**
    Constructor
    @param tokenForge Token forge to use
    @param address URI of access token endpoint
     */
    public ATI2(TokenForge tokenForge, URI address,boolean isOIDC) {
        super(tokenForge, address);
        this.isOIDC = isOIDC;
    }

    /**
    Processes access token request
    @param accessTokenRequest Access token request
    @return Access token response
     */
    public ATResponse processATRequest(ATRequest accessTokenRequest) {
        Map<String,String> reqParamMap = OA2Utilities.getParameters(accessTokenRequest.getServletRequest());
        // get access token
        RTIRequest rtiRequest = new RTIRequest(accessTokenRequest.getTransaction(), accessTokenRequest.isOidc());
        OA2TokenForge tf2 = (OA2TokenForge) tokenForge;
        AccessTokenImpl accessToken =tf2.createToken(accessTokenRequest);
        RefreshTokenImpl refreshToken = tf2.createToken(rtiRequest);
        ATIResponse2 atResp = new ATIResponse2(accessToken, refreshToken, accessTokenRequest.isOidc());
        atResp.setParameters(reqParamMap);
        atResp.setServiceTransaction(accessTokenRequest.getTransaction());
        return atResp;
    }
}
