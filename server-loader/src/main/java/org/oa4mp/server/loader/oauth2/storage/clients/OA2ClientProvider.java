package org.oa4mp.server.loader.oauth2.storage.clients;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifierProvider;
import org.oa4mp.delegation.common.storage.clients.ClientProvider;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/14/14 at  12:42 PM
 */
public class OA2ClientProvider<V extends OA2Client> extends ClientProvider<V> {
    @Override
    protected V newClient(boolean createNewIdentifier) {
       return (V) new OA2Client(createNewId(createNewIdentifier));
    }

    public OA2ClientProvider(IdentifierProvider<Identifier> idProvider) {
        super(idProvider);

    }
}