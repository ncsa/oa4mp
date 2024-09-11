package org.oa4mp.client.loader;

import org.oa4mp.client.api.ClientEnvironment;
import org.oa4mp.client.api.OA4MPService;
import org.oa4mp.client.api.OA4MPServiceProvider;

/**
 * Service provider for the OA4MP service.
 * <p>Created by Jeff Gaynor<br>
 * on 2/25/14 at  10:17 AM
 */
public class OA2MPServiceProvider extends OA4MPServiceProvider {
    protected ClientEnvironment oa2ClientEnvironment;
    public OA2MPServiceProvider(ClientEnvironment oa2ClientEnvironment) {
        super();
        this.oa2ClientEnvironment = oa2ClientEnvironment;
    }

    @Override
    public OA4MPService get() {
        return new OA2MPService(oa2ClientEnvironment);
    }
}
