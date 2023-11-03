package edu.uiuc.ncsa.oa4mp.delegation.oa2.client;

import edu.uiuc.ncsa.oa4mp.delegation.client.request.RTRequest;
import edu.uiuc.ncsa.oa4mp.delegation.client.request.RTResponse;
import edu.uiuc.ncsa.oa4mp.delegation.client.server.RTServer;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.Client;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AccessToken;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.RefreshToken;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.IDTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.RefreshTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.TokenFactory;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Constants;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.servlet.ServiceClient;
import net.sf.json.JSONObject;

import java.net.URI;
import java.util.HashMap;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/26/14 at  2:18 PM
 */
public class RTServer2 extends TokenAwareServer implements RTServer {

    public RTServer2(ServiceClient serviceClient, String wellknown, boolean oidcEnabled) {
        super(serviceClient, wellknown, oidcEnabled);
    }

    @Override
    public RTResponse processRTRequest(RTRequest rtRequest) {
        AccessToken accessToken = rtRequest.getAccessToken();
        RefreshToken refreshToken = rtRequest.getRefreshToken();
        if (refreshToken == null) {
            throw new GeneralException("there is no refresh token, so it is not possible to refresh it.");
        }
        String raw = getRTResponse(getAddress(), rtRequest);
        JSONObject json = getAndCheckResponse(raw);
        String returnedAT = json.getString(OA2Constants.ACCESS_TOKEN);

        if (accessToken.getToken().equals(returnedAT)) {
            throw new IllegalArgumentException("the returned access token from the server should not match the one in the request.");
        }
        String exp = json.getString(OA2Constants.EXPIRES_IN);
        if (exp == null || exp.length() == 0) {
            throw new IllegalArgumentException("missing expires_in field from server");
        }
        RefreshTokenImpl refreshTokenImpl2 = TokenFactory.createRT(json.getString(OA2Constants.REFRESH_TOKEN));
        AccessTokenImpl newAT = TokenFactory.createAT(returnedAT);
        IDTokenImpl idToken = null;
        if (serverOIDCEnabled) {
            idToken = getAndCheckIDToken(json, rtRequest);
        }
        RTResponse rtResponse = createResponse(newAT, refreshTokenImpl2, idToken);
        return rtResponse;
    }

    protected String getRTResponse(URI uri,  RTRequest rtRequest) {
        HashMap map = new HashMap();
        map.put(OA2Constants.GRANT_TYPE, OA2Constants.REFRESH_TOKEN);
        map.put(OA2Constants.REFRESH_TOKEN, rtRequest.getRefreshToken().getToken());
        map.putAll(rtRequest.getParameters());
        Client client = rtRequest.getClient();
        String response;
        if(client.hasJWKS()){
              response = RFC7523Utils.doPost(getServiceClient(), client, getTokenEndpoint(), rtRequest.getKeyID(),map);
        }else {
            map.put(OA2Constants.CLIENT_ID, client.getIdentifierString());
            map.put(OA2Constants.CLIENT_SECRET, client.getSecret());
            response = getServiceClient().doGet(map);
        }
        return response;
    }

    public RTResponse createResponse(AccessTokenImpl at, RefreshTokenImpl rt, IDTokenImpl idToken) {
        return new RTResponse(at, rt, idToken);
    }
}
