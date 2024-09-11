package org.oa4mp.server.api.admin.adminClient;

import org.oa4mp.server.api.admin.transactions.OA4MPIdentifierProvider;
import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;

import java.util.Date;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/20/16 at  1:08 PM
 */
public class AdminClientProvider<V extends AdminClient> extends IdentifiableProviderImpl<V> {
    public AdminClientProvider() {
        super(new OA4MPIdentifierProvider(OA4MPIdentifierProvider.ADMIN_CLIENT_ID));
    }

    @Override
    public V get(boolean createNewIdentifier) {
        V v = (V) new AdminClient(createNewId(createNewIdentifier));
        v.setCreationTS(new Date());
        v.setDebugOn(true); // default for admin clients
        return v;
    }
}
