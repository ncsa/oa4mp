package edu.uiuc.ncsa.oa4mp.delegation.oa2.client;

import edu.uiuc.ncsa.security.servlet.ServiceClient;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 7/19/23 at  9:29 AM
 */
public class RFC8623Server extends TokenAwareServer{
    public RFC8623Server(ServiceClient serviceClient, String wellKnown, boolean oidcEnabled) {
        super(serviceClient, wellKnown, oidcEnabled);
    }

}
