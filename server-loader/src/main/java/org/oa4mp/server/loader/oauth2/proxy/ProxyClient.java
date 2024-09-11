package org.oa4mp.server.loader.oauth2.proxy;

import org.oa4mp.client.api.ClientEnvironment;
import org.oa4mp.client.api.OA4MPResponse;
import org.oa4mp.client.loader.OA2MPService;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;

import java.net.URI;
import java.util.Map;

/**
 * This is used as a proxy client. This allows for an OA4MP server to replace its
 * authorization machinery by delegating to another OAuth service.
 * <p>Created by Jeff Gaynor<br>
 * on 1/4/22 at  2:44 PM
 */
public class ProxyClient {
    protected OA2MPService service;

     public OA2MPService getService() {
         if (service == null) {
             service = new OA2MPService(getCe());
         }
         return service;
     }
    public ClientEnvironment getCe() {
        return ce;
    }

    public void setCe(ClientEnvironment ce) {
        this.ce = ce;
    }

    protected ClientEnvironment ce;

    /**
     * Create the URI to start a standard flow from the client configuration.
     * @return
     */
     public URI createRedirect(){
         Map<String, String> requestParameters = null;
         Identifier id = null; // for the asset, which we do not support.
         OA4MPResponse resp = getService().requestCert(id, requestParameters);
         DebugUtil.trace(this, "client id = " + getCe().getClientId());
         URI currentURI = resp.getRedirect();
         return currentURI;
     }

    /**
     * Starts a device code flow from the configuration.
     */
    public void deviceFlow(){
         
     }
     
}
