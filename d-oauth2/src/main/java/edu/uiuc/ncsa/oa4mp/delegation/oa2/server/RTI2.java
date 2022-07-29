package edu.uiuc.ncsa.oa4mp.delegation.oa2.server;

import edu.uiuc.ncsa.oa4mp.delegation.server.issuers.AbstractIssuer;
import edu.uiuc.ncsa.oa4mp.delegation.server.request.ATRequest;
import edu.uiuc.ncsa.oa4mp.delegation.server.request.IssuerRequest;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.TokenForge;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.RefreshTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Constants;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2TokenForge;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Utilities;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;

import java.net.URI;
import java.util.Map;

/**
 * Refresh Token Issuer for OAuth2.
 * <p>Created by Jeff Gaynor<br>
 * on 2/26/14 at  10:03 AM
 */
public class RTI2 extends AbstractIssuer {
    public RTI2(TokenForge tokenForge, URI address) {
        super(tokenForge, address);
    }

    public IResponse2 processRTRequest(IssuerRequest req, boolean isOIDC) {

        RTIRequest request = (RTIRequest) req;
        Map<String, String> reqParamMap = OA2Utilities.getParameters(request.getServletRequest());
        ServletDebugUtil.trace(this,"Request parameters:" + reqParamMap);
        reqParamMap.put(OA2Constants.CLIENT_ID, req.getClient().getIdentifierString());
        OA2TokenForge tokenForge2 = (OA2TokenForge) tokenForge;
        RefreshTokenImpl refreshToken = tokenForge2.createToken(request);
        ATRequest atRequest = new ATRequest(null, request.getTransaction());
        AccessTokenImpl accessToken = tokenForge2.createToken(atRequest);
        // spec says all new access token
        RTIResponse resp = new RTIResponse(accessToken, refreshToken, isOIDC);
        resp.setParameters(reqParamMap);
        return resp;
    }
}
