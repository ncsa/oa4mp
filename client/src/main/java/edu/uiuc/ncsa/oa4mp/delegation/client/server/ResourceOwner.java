package edu.uiuc.ncsa.oa4mp.delegation.client.server;

import edu.uiuc.ncsa.oa4mp.delegation.common.services.AddressableServer;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AuthorizationGrant;

/**
 * Models the owner of the resource (e.g. a person).
 * <p>Created by Jeff Gaynor<br>
 * on Mar 11, 2011 at  4:09:29 PM
 */
public interface ResourceOwner extends AddressableServer {
    AuthorizationGrant grantAuthorization();
}
