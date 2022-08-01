package edu.uiuc.ncsa.oa4mp.delegation.oa2.client;

import edu.uiuc.ncsa.oa4mp.delegation.client.request.UIRequest;
import edu.uiuc.ncsa.oa4mp.delegation.client.request.UIResponse;
import edu.uiuc.ncsa.oa4mp.delegation.client.server.UIServer;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Constants;
import edu.uiuc.ncsa.security.servlet.ServiceClient;

import java.util.HashMap;

/**
 * Handles client UserInfo request to server
 */

public class UIServer2 extends ASImpl implements UIServer {
    ServiceClient serviceClient;
        public ServiceClient getServiceClient() {
            return serviceClient;
        }

    public UIServer2(ServiceClient serviceClient) {
        super(serviceClient.host());
        this.serviceClient = serviceClient;
    }

    /**
     * Processes UserInfo request
     *
     * @param uiRequest User info request
     * @return User Info response
     */
    public UIResponse processUIRequest(UIRequest uiRequest) {
        HashMap m = new HashMap();
       m.put(OA2Constants.ACCESS_TOKEN, uiRequest.getAccessToken().getToken());
        String response = getServiceClient().doGet(m);
    return new UIResponse(uiRequest.getAccessToken(), response);
    }
}
