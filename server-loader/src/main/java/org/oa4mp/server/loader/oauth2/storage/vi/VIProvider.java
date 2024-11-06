package org.oa4mp.server.loader.oauth2.storage.vi;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;
import org.oa4mp.delegation.server.OA2TokenForge;

import javax.inject.Provider;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/20 at  10:43 AM
 */
public class VIProvider<V extends VirtualIssuer> extends IdentifiableProviderImpl<V> {
    public VIProvider(Provider<Identifier> idProvider, OA2TokenForge tokenForge) {
        super(idProvider);
        this.tokenForge = tokenForge;
    }


    OA2TokenForge tokenForge;

    @Override
    public V get(boolean createNewIdentifier) {
        V vo = (V) new VirtualIssuer(BasicIdentifier.newID(tokenForge.getAuthorizationGrant().getToken()));
        return vo;
    }
}
