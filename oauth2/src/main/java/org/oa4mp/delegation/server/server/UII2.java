package org.oa4mp.delegation.server.server;

import org.oa4mp.delegation.server.issuers.AbstractIssuer;
import org.oa4mp.delegation.common.token.TokenForge;
import org.oa4mp.delegation.server.OA2Utilities;
import org.oa4mp.delegation.server.UserInfo;

import java.net.URI;
import java.util.Map;

/**
 * UserInfo issuer for OAuth 2 class
 * <p>Created by Jeff Gaynor<br>
 * on 10/7/13 at  2:35 PM
 */
public class UII2 extends AbstractIssuer {

    /**
     * Constructor
     *
     * @param tokenForge Token forge to use
     * @param address    URI of UserInfo endpoint on server
     */
    public UII2(TokenForge tokenForge, URI address) {
        super(tokenForge, address);
    }

    /**
     * @param request User info request
     * @return User info response
     */
    public UIIResponse2 processUIRequest(UIIRequest2 request) {
        Map<String, String> reqParamMap = OA2Utilities.getParameters(request.getServletRequest());
        UIIResponse2 uiiResponse2 = new UIIResponse2();
        uiiResponse2.setParameters(reqParamMap);
        uiiResponse2.setAccessToken(request.getAccessToken());
        UserInfo userInfo = new UserInfo();
        userInfo.setSub(request.getUsername());
        uiiResponse2.setUserInfo(userInfo);
        return uiiResponse2;
    }

}
