package edu.uiuc.ncsa.oa4mp.delegation.common.services;

/**
 * A server that processes via double dispatch. In this case, a {@link Request} object
 * points to an instance of this interface and calls its process method. (In Java,
 * passing in arguments will not necessarily have them resolved correctly, so
 * having an object tasked with only invoking against the runtime class is required.
 * This could have been done with a slew of else-if statements, but that gets pretty hard
 * to deal with if the classes are extended.)
 * <p>Created by Jeff Gaynor<br>
 * on 6/3/13 at  10:51 AM
 */
public interface DoubleDispatchServer {
     Response process(Request request);
}
