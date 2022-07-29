package edu.uiuc.ncsa.oa4mp.delegation.oa2.server;

import edu.uiuc.ncsa.oa4mp.delegation.server.issuers.ATIssuer;
import edu.uiuc.ncsa.oa4mp.delegation.server.issuers.AbstractIssuer;
import edu.uiuc.ncsa.oa4mp.delegation.server.request.ATRequest;
import edu.uiuc.ncsa.oa4mp.delegation.server.request.ATResponse;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.TokenForge;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.RefreshTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2TokenForge;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Utilities;

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
    @address URI of access token endpoint
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
        RTIRequest rtiRequest = new RTIRequest(accessTokenRequest.getTransaction(), isOIDC);
        OA2TokenForge tf2 = (OA2TokenForge) tokenForge;
        AccessTokenImpl accessToken =tf2.createToken(accessTokenRequest);
        RefreshTokenImpl refreshToken = tf2.createToken(rtiRequest);
        ATIResponse2 atResp = new ATIResponse2(accessToken, refreshToken, isOIDC);
        atResp.setParameters(reqParamMap);
        atResp.setServiceTransaction(accessTokenRequest.getTransaction());
        return atResp;
    }
}
