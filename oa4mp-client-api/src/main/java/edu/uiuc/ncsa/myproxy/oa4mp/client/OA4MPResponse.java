package edu.uiuc.ncsa.myproxy.oa4mp.client;


import edu.uiuc.ncsa.security.delegation.services.Response;

import java.net.URI;
import java.security.PrivateKey;


/**
 * Response from initial call to the {@link OA4MPService}. This will contain the redirect and private key
 * that was created. The resulting certificate will not be usable unless this key is available, so it is
 * up to clients to store this someplace.
 * <p>Created by Jeff Gaynor<br>
 * on May 16, 2011 at  3:30:27 PM
 */
public class OA4MPResponse implements Response {
    public URI getRedirect() {
        return redirect;
    }

    public void setRedirect(URI redirect) {
        this.redirect = redirect;
    }

    URI redirect;

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    PrivateKey privateKey;

    @Override
    public String toString() {
        return "MyProxyDSResponse[redirect=" + getRedirect() + ", privateKey " + (getPrivateKey() == null ? "=" : "!") + "= null]";
    }
}
