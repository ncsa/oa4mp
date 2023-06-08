package edu.uiuc.ncsa.oa4mp.delegation.oa2.client;

import edu.uiuc.ncsa.oa4mp.delegation.client.AbstractClientEnvironment;
import edu.uiuc.ncsa.oa4mp.delegation.client.request.PARequest;
import edu.uiuc.ncsa.oa4mp.delegation.client.request.PAResponse;
import edu.uiuc.ncsa.oa4mp.delegation.client.server.PAServer;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Constants;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.Client;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AccessToken;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.MyX509Certificates;
import edu.uiuc.ncsa.security.servlet.ServiceClient;
import edu.uiuc.ncsa.security.util.pkcs.MyCertUtil;

import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;

/**
 * Handles client call for protected asset (cert?) request
 * <p>Created by Jeff Gaynor<br>
 * on 6/4/13 at  4:33 PM
 */
public class PAServer2 extends ASImpl implements PAServer {
    ServiceClient serviceClient;
        public ServiceClient getServiceClient() {
            return serviceClient;
        }

    public PAServer2(ServiceClient serviceClient) {
        super(serviceClient.host());
        this.serviceClient = serviceClient;
    }

    /**
     * Processes protected asset request
     *
     * @param request PA/cert request
     * @return asset
     */
    public PAResponse processPARequest(PARequest request) {
        return getAsset(request.getClient(), request.getParameters(), request.getAccessToken());
    }

    /**
     * Gets asset
     *
     * @param client      Client ID
     * @param props       Map of properties
     * @param accessToken Access token
     * @return asset
     */
    protected PAResponse getAsset(Client client, Map props, AccessToken accessToken) {
        HashMap m = new HashMap();
        m.put(OA2Constants.ACCESS_TOKEN, accessToken.getToken().toString());
        m.put(OA2Constants.CLIENT_ID, client.getIdentifierString());
        m.put(OA2Constants.CLIENT_SECRET, client.getSecret());
        m.put(OA2Constants.REDIRECT_URI,  props.get(OA2Constants.REDIRECT_URI));
        m.put(OA2Constants.CERT_REQ, String.valueOf(props.get(AbstractClientEnvironment.CERT_REQUEST_KEY)));
        m.put(OA2Constants.CERT_LIFETIME, String.valueOf(props.get(AbstractClientEnvironment.CERT_LIFETIME_KEY)));
        String response = getServiceClient().doGet(m); // No JSON in the spec. Just a string of certs.
        MyX509Certificates myX509Certificate = null;
        try {
            myX509Certificate = new MyX509Certificates(MyCertUtil.fromX509PEM(response));
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        PAResponse par = new PAResponse(myX509Certificate);
        return par;


    }
}
