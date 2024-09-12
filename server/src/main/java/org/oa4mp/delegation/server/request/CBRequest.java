package org.oa4mp.delegation.server.request;

import org.oa4mp.delegation.server.ServiceTransaction;
import org.oa4mp.delegation.server.issuers.CBIssuer;
import org.oa4mp.delegation.common.services.Response;
import org.oa4mp.delegation.common.services.Server;
import org.oa4mp.delegation.common.token.AuthorizationGrant;
import org.oa4mp.delegation.common.token.Verifier;

import java.net.URI;

/**
 * Request to a callback server.
 * <br>OAuth 1 specific.
 * <p>Created by Jeff Gaynor<br>
 * on May 23, 2011 at  11:30:10 AM
 */
public class CBRequest extends IssuerRequest {
    @Override
    public int getType() {
        return CB_TYPE;
    }

    /**
     * How long should the issuer wait for a response to this request? A value of 0 (or less)
     * means to accept whatever the defaults are for the underlying library.
     *
     * @return
     */
    public int getConnectionTimeout() {
        return connectionTimeout;
    }

    public void setConnectionTimeout(int connectionTimeout) {
        this.connectionTimeout = connectionTimeout;
    }

    int connectionTimeout = 0;

    @Override
    public Response process(Server server) {
        if (server instanceof CBIssuer) {
            return ((CBIssuer) server).processCallbackRequest(this);
        }
        return super.process(server);
    }

    AuthorizationGrant authorizationGrant;

    public AuthorizationGrant getAuthorizationGrant() {
        return authorizationGrant;
    }

    public void setAuthorizationGrant(AuthorizationGrant authorizationGrant) {
        this.authorizationGrant = authorizationGrant;
    }

    public URI getCallbackUri() {
        return callbackUri;
    }

    public void setCallbackUri(URI callbackUri) {
        this.callbackUri = callbackUri;
    }

    public Verifier getVerifier() {
        return verifier;
    }

    public void setVerifier(Verifier verifier) {
        this.verifier = verifier;
    }

    Verifier verifier;
    URI callbackUri;

    public CBRequest(ServiceTransaction transaction) {
        super(transaction);

    }

    @Override
    public String toString() {
        return "CBRequest[grant=" + authorizationGrant + ", uri=" + callbackUri + ", verifier=" + verifier + "]";
    }
}
