package org.oa4mp.delegation.server.client;

import edu.uiuc.ncsa.security.servlet.ServiceClient;

import java.net.URI;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 7/19/23 at  9:29 AM
 */
public class RFC8623Server extends TokenAwareServer{
    public RFC8623Server(ServiceClient serviceClient, URI issuer, String wellKnown, boolean oidcEnabled) {
        super(serviceClient, issuer, wellKnown, oidcEnabled);
    }

}
