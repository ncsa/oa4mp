package org.oa4mp.delegation.server.server.claims;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/19/16 at  11:26 AM
 */
public abstract class ClaimSourceFactory {
    public ClaimSourceFactory() {
    }

    public static ClaimSourceFactory getFactory() {
        return factory;
    }

    public static void setFactory(ClaimSourceFactory factory) {
        ClaimSourceFactory.factory = factory;
    }

    static ClaimSourceFactory factory;

    public  abstract ClaimSource create(ClaimSourceFactoryRequest request);

    public static ClaimSource newInstance(ClaimSourceFactoryRequest request){
        return getFactory().create(request);
    }

    public static boolean isFactorySet(){
        return factory != null;
    }
}
