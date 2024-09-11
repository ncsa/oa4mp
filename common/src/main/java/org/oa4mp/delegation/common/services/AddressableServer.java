package org.oa4mp.delegation.common.services;

import java.net.URI;

/**
 * A server that can be accessed via a URI.
 * <p>Created by Jeff Gaynor<br>
 * on Mar 16, 2011 at  2:37:04 PM
 */
public interface AddressableServer extends Server {
    URI getAddress();
}
