package org.oa4mp.delegation.server.client;

import edu.uiuc.ncsa.security.servlet.ServiceClient;
import org.oa4mp.delegation.client.DelegationService;
import org.oa4mp.delegation.client.request.*;
import org.oa4mp.delegation.client.server.*;
import org.oa4mp.delegation.common.token.AccessToken;
import org.oa4mp.delegation.common.token.RefreshToken;
import org.oa4mp.delegation.server.OA2Constants;

import java.net.URI;
import java.util.Map;

/**
 * Delegation service for OIDC
 * <p>Created by Jeff Gaynor<br>
 * on 11/25/13 at  2:20 PM
 */
public class DS2 extends DelegationService {
    UIServer2 uiServer;

    /**
     * Constructor
     *
     * @param agServer Authorization grant handler for client
     * @param atServer Access token handler for client
     * @param paServer Protected asset (cert) request handler for client
     * @param uiServer UserInfo handler for client
     */
    public DS2(AGServer agServer,
               ATServer atServer,
               PAServer paServer,
               UIServer2 uiServer,
               RTServer rtServer,
               RFC7009Server rfc7009Server,
               RFC7662Server rfc7662Server,
               RFC7523Server rfc7523Server,
               RFC8623Server rfc8623Server) {
        super(agServer, atServer, paServer);
        this.uiServer = uiServer;
        this.rtServer = rtServer;
        this.rfc7009Server = rfc7009Server;
        this.rfc7662Server = rfc7662Server;
        this.rfc7523Server = rfc7523Server;
        this.rfc8623Server = rfc8623Server;
    }

    public RFC8623Server getRfc8623Server() {
        return rfc8623Server;
    }

    public void setRfc8623Server(RFC8623Server rfc8623Server) {
        this.rfc8623Server = rfc8623Server;
    }

    RFC8623Server rfc8623Server;
    RFC7523Server rfc7523Server;
    RTServer rtServer;

    /**
     * Getter for UIServer
     *
     * @return UserInfo handler
     */
    public UIServer2 getUiServer() {
        return uiServer;
    }


    public UIResponse getUserInfo(UIRequest uiRequest) {
        return (UIResponse) getUiServer().process(uiRequest);
    }

    public RTServer getRtServer() {
        return rtServer;
    }

    public void setRtServer(RTServer rtServer) {
        this.rtServer = rtServer;
    }

    /**
     * As per spec., issue request for refresh from server. Returned {@link RTResponse} has the associated
     * {@link RefreshToken} and {@link AccessToken}.
     *
     * @return
     */
    public RTResponse refresh(RTRequest refreshTokenRequest) {
        return (RTResponse) getRtServer().process(refreshTokenRequest);
    }

    public RFC7009Response rfc7009(RFC7009Request request) {
        return  getRfc7009Server().processRFC7009Request(request);
    }

    public RFC7662Response rfc7662(RFC7662Request request) {
        return getRfc7662Server().processRFC7662Request(request);
    }

    public RFC7523Response rfc7523(RFC7523Request request){
       return rfc7523Server.processRFC7523Request(request);
    }
    @Override
    public DelegationResponse processDelegationRequest(DelegationRequest delegationRequest) {
        DelegationResponse delResp = new DelegationResponse(null);
        Map<String,String> m = delegationRequest.getParameters();
        m.put(OA2Constants.CLIENT_ID, delegationRequest.getClient().getIdentifierString());
        m.put(OA2Constants.REDIRECT_URI, delegationRequest.getParameters().get(OA2Constants.REDIRECT_URI));
        URI authZUri = ((AGServer2)getAgServer()).getServiceClient().host();
        URI redirectURI = URI.create(ServiceClient.convertToStringRequest(authZUri.toString(), m));
        delResp.setParameters(m); //send them all back.
        delResp.setRedirectUri(redirectURI);
        return delResp;

    }

    /**
     * Creates redirect URL
     *
     * @param delegationAssetRequest Delegation asset request
     * @param agResp                 Authorization grant response
     * @return URI for redirect
     */
    @Override
    public URI createRedirectURL(DelegationRequest delegationAssetRequest, AGResponse agResp) {
        String rc = delegationAssetRequest.getBaseUri().toString() +
                "?" + OA2Constants.AUTHORIZATION_CODE + "=" + agResp.getAuthorizationGrant().getToken();
        Object state = agResp.getParameters().get(OA2Constants.STATE);
        // As per spec, only return the state if it was sent in the first place.
        if (state != null) {
            rc = rc + "&" + OA2Constants.STATE + "=" + state;
        }
        return URI.create(rc);
    }
    public RFC7662Server getRfc7662Server() {
        return rfc7662Server;
    }


    RFC7662Server rfc7662Server;

    public RFC7009Server getRfc7009Server() {
        return rfc7009Server;
    }

    RFC7009Server rfc7009Server;


}
