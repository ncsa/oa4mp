package org.oa4mp.delegation.server.client;

import org.oa4mp.delegation.request.UIRequest;
import org.oa4mp.delegation.request.UIResponse;
import org.oa4mp.delegation.server.UIServer;
import org.oa4mp.delegation.server.OA2Constants;
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
