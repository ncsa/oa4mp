package org.oa4mp.delegation.server.issuers;

import org.oa4mp.delegation.common.services.DoubleDispatchServer;
import org.oa4mp.delegation.common.token.TokenForge;

import javax.inject.Provider;
import java.net.URI;

/**
 * Abstract factory for issuers.
 * <p>Created by Jeff Gaynor<br>
 * on 4/26/12 at  1:37 PM
 */
public abstract class IssuerProvider<T extends DoubleDispatchServer> implements Provider<T> {
    protected TokenForge tokenForge;
    protected URI address;

    protected IssuerProvider(TokenForge tokenForge, URI address) {
        this.address = address;
        this.tokenForge = tokenForge;
    }
}
