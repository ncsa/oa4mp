package org.oa4mp.delegation.request;

import org.oa4mp.delegation.server.ATServer;
import org.oa4mp.delegation.common.services.Response;
import org.oa4mp.delegation.common.services.Server;
import org.oa4mp.delegation.common.token.AuthorizationGrant;
import org.oa4mp.delegation.common.token.Verifier;

/**
 * <p>Created by Jeff Gaynor<br>
 * on Apr 13, 2011 at  4:02:13 PM
 */
public class ATRequest extends BasicRequest {
    public ATRequest() {
    }

    /**
     * Pending removal of OAuth 1 stuff, this is about the best we are going to do.
     * Have to stick stuff inside classes and use facades to pass newer parameters...
     * @param dar
     */
    public ATRequest(DelegatedAssetRequest dar) {
        setVerifier(dar.getVerifier());
        setRfc8628(dar.isRfc8628());
        setAuthorizationGrant(dar.getAuthorizationGrant());
        setClient(dar.getClient());
        setParameters(dar.getParameters());
        setKeyID(dar.getKeyID());
    }

    /**
     * Optional if supported. This should be set to null if it is not supported.
     *
     * @return
     */
    public Verifier getVerifier() {
        return verifier;
    }

    public void setVerifier(Verifier verifier) {
        this.verifier = verifier;
    }

    Verifier verifier;

    public Response process(Server server) {
        if (server instanceof ATServer) {
            return ((ATServer) server).processATRequest(this);
        }
        return super.process(server);
    }


    public AuthorizationGrant getAuthorizationGrant() {
        return authorizationGrant;
    }

    public void setAuthorizationGrant(AuthorizationGrant authorizationGrant) {
        this.authorizationGrant = authorizationGrant;
    }

    AuthorizationGrant authorizationGrant;

    public boolean isRfc8628() {
        return rfc8628;
    }

    public void setRfc8628(boolean rfc8628) {
        this.rfc8628 = rfc8628;
    }

    boolean rfc8628 = false;
}
