package org.oa4mp.delegation;

import javax.inject.Provider;
import java.net.URI;

/**
 * A provider (i.e. factory) that creates {@link DelegationService} instances.
 * <p>Created by Jeff Gaynor<br>
 * on 4/12/12 at  11:47 AM
 */
public abstract class AbstractDelegationServiceProvider implements Provider<DelegationService> {
    protected URI grantServerURI;
    protected URI accessServerURI;
    protected URI assetServerURI;

    protected AbstractDelegationServiceProvider(URI grantServerURI,
                                                URI accessServerURI,
                                                URI assetServerURI) {
        this.accessServerURI = accessServerURI;
        this.assetServerURI = assetServerURI;
        this.grantServerURI = grantServerURI;
    }
}
