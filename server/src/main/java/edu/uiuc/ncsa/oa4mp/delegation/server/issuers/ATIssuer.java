package edu.uiuc.ncsa.oa4mp.delegation.server.issuers;

import edu.uiuc.ncsa.oa4mp.delegation.server.request.ATRequest;
import edu.uiuc.ncsa.oa4mp.delegation.server.request.ATResponse;
import org.oa4mp.delegation.common.services.DoubleDispatchServer;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/3/13 at  3:34 PM
 */
public interface ATIssuer extends DoubleDispatchServer {
    public abstract ATResponse processATRequest(ATRequest accessTokenRequest);

}
