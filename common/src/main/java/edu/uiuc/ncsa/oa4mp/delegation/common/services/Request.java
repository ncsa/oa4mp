package edu.uiuc.ncsa.oa4mp.delegation.common.services;

/**
 * General delegation request to a service
 * <p>Created by Jeff Gaynor<br>
 * on Apr 13, 2011 at  3:32:38 PM
 */
public interface Request {
    /**
     * Process the request
     * @param server
     * @return
     */
    Response process(Server server);

}
