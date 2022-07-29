package edu.uiuc.ncsa.oa4mp.delegation.server.request;

import edu.uiuc.ncsa.oa4mp.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AuthorizationGrant;

/**
 * Server response to a request for an {@link AuthorizationGrant}.
 * <p>Created by Jeff Gaynor<br>
 * on May 13, 2011 at  12:35:25 PM
 */
public interface AGResponse extends IssuerResponse {
    public AuthorizationGrant getGrant();
    public ServiceTransaction getServiceTransaction();
    public void setServiceTransaction(ServiceTransaction transaction);
}
