package edu.uiuc.ncsa.co.util.attributes;

import edu.uiuc.ncsa.security.delegation.services.DoubleDispatchServer;
import edu.uiuc.ncsa.security.delegation.services.Request;
import edu.uiuc.ncsa.security.delegation.services.Response;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/28/16 at  1:31 PM
 */
public class AttributeServer implements DoubleDispatchServer {
    @Override
    public Response process(Request request) {
        return null;
    }

    public AttributeResponse get(AttributeRequest request){
        return null;
    }

    public AttributeResponse set(AttributeRequest request){
        return null;
    }

    public AttributeResponse remove(AttributeRequest request){
        return null;
    }

    public AttributeResponse list(AttributeRequest request){
        return null;
    }
}
