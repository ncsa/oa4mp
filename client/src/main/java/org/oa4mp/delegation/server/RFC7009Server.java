package org.oa4mp.delegation.server;

import org.oa4mp.delegation.request.RFC7009Request;
import org.oa4mp.delegation.request.RFC7009Response;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/19/21 at  6:29 AM
 */
public interface RFC7009Server {
    RFC7009Response processRFC7009Request(RFC7009Request request);
}
