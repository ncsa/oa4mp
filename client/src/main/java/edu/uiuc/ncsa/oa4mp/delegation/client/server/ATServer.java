package edu.uiuc.ncsa.oa4mp.delegation.client.server;

import edu.uiuc.ncsa.oa4mp.delegation.client.request.ATRequest;
import edu.uiuc.ncsa.oa4mp.delegation.client.request.ATResponse;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.DoubleDispatchServer;

/**
 * For a server that is tasked with creating access tokens. The request must contain a valid grant.
 * <p>Created by Jeff Gaynor<br>
 * on 6/3/13 at  10:45 AM
 */
public interface ATServer extends DoubleDispatchServer {
     ATResponse processATRequest(ATRequest atRequest);
}
