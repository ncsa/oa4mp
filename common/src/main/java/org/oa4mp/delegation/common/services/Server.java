package org.oa4mp.delegation.common.services;

/**
 * Top-level model for any server. All servers in this module use double-dispatch to decouple
 * the various types of implementations from the main control flows. Servers get requests which
 * they invoke process on. The Request then invokes process on the server. The server has
 * polymorphic methods for each type of request and the request then is routed to one of those.
 * <p>Created by Jeff Gaynor<br>
 * on Apr 13, 2011 at  3:33:28 PM
 */
public interface Server {
    Response process(Request request);
}
