package org.oa4mp.delegation.server;

import org.oa4mp.delegation.request.RFC7662Request;
import org.oa4mp.delegation.request.RFC7662Response;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/19/21 at  6:21 AM
 */
public interface RFC7662Server {
    RFC7662Response processRFC7662Request(RFC7662Request request);
}
