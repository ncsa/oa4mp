package edu.uiuc.ncsa.myproxy.oa4mp.client;

import javax.inject.Provider;

/**
 * An internal factory for making an {@link OA4MPService} instance. This is generally not
 * needed by implementers.
 * <p>Created by Jeff Gaynor<br>
 * on 6/26/12 at  10:41 AM
 */
public class OA4MPServiceProvider implements Provider<OA4MPService> {

    protected ClientEnvironment clientEnvironment;

    public OA4MPServiceProvider(ClientEnvironment clientEnvironment) {
        this.clientEnvironment = clientEnvironment;
    }

    @Override
    public OA4MPService get() {
        return new OA4MPService(clientEnvironment);
    }
}
