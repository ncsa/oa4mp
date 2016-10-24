package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.OA4MPIdentifierProvider;
import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;

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
        return (V) new AdminClient(createNewId(createNewIdentifier));
    }
}
