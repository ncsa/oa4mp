package org.oa4mp.delegation.server.issuers;

import org.oa4mp.delegation.server.request.PARequest;
import org.oa4mp.delegation.server.request.PAResponse;
import org.oa4mp.delegation.common.services.DoubleDispatchServer;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/3/13 at  3:35 PM
 */
public interface PAIssuer extends DoubleDispatchServer {
    public PAResponse processProtectedAsset(PARequest paRequest);
}
