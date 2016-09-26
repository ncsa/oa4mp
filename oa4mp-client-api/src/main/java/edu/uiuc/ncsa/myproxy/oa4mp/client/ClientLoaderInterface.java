package edu.uiuc.ncsa.myproxy.oa4mp.client;

/**
 * An interface ensuring that loaders have a service provider.
 * <p>Created by Jeff Gaynor<br>
 * on 6/26/12 at  10:52 AM
 */
public interface ClientLoaderInterface {
    /**
     * The provider that creates an instance of the {@link OA4MPService}
     * @return
     */
    public OA4MPServiceProvider getServiceProvider();
}
