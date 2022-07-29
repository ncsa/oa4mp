package edu.uiuc.ncsa.oa4mp.delegation.client.request;

import edu.uiuc.ncsa.oa4mp.delegation.client.DelegationService;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Response;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Server;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AuthorizationGrant;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.Verifier;

import java.util.Map;

/**
 * Get an asset using delegation.
 * <p>Created by Jeff Gaynor<br>
 * on Apr 15, 2011 at  11:12:03 AM
 */
public class DelegatedAssetRequest extends BasicRequest {

    public Response process(Server server) {
        if (server instanceof DelegationService) {
            return ((DelegationService) server).processAssetRequest(this);
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


    public Verifier getVerifier() {
        return verifier;
    }

    public void setVerifier(Verifier verifier) {
        this.verifier = verifier;
    }

    Verifier verifier;

    /**
     * These are passed to the resource server in the protected asset request. The {@link #getParameters()} are passed
     * to the authorization server.
     *
     * @return
     */
    public Map getAssetParameters() {
        return assetParameters;
    }

    public void setAssetParameters(Map assetParameters) {
        this.assetParameters = assetParameters;
    }

    Map assetParameters;

    public boolean isRfc8628() {
        return rfc8628;
    }

    public void setRfc8628(boolean rfc8628) {
        this.rfc8628 = rfc8628;
    }

    boolean rfc8628 = false;
}
